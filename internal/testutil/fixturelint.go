package testutil

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// FixtureIssue identifies a literal ID fixture with the wrong production shape.
type FixtureIssue struct {
	Line    int
	Message string
}

// LintIDFixtures checks exported ID fields in struct literals, literal IDs
// assigned to ID-named variables, selected store-creation arguments, and raw
// JSON ID fields. It evaluates constant concatenation, Sprintf and Repeat;
// named ID builders guarantee shape even with a dynamic label. This bounded
// source lint does not attempt whole-program data-flow analysis.
func LintIDFixtures(filename string, source []byte, prefixes map[string]bool) ([]FixtureIssue, error) {
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, filename, source, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	comments := map[int]string{}
	for _, g := range file.Comments {
		for _, c := range g.List {
			comments[fs.Position(c.Pos()).Line] = c.Text
		}
	}
	var issues []FixtureIssue
	seen := map[string]bool{}
	report := func(n ast.Node, message string) {
		line := fs.Position(n.End()).Line
		comment := comments[line]
		if strings.HasPrefix(comment, "// malformed:") && strings.TrimSpace(strings.TrimPrefix(comment, "// malformed:")) != "" {
			return
		}
		key := fmt.Sprintf("%d:%s", line, message)
		if !seen[key] {
			seen[key] = true
			issues = append(issues, FixtureIssue{line, message})
		}
	}
	check := func(n ast.Expr, prefix string) {
		if !prefixes[prefix] {
			return
		}
		value, known := fixtureString(n)
		if !known {
			switch v := n.(type) {
			case *ast.BinaryExpr:
				report(n, "unsupported ID fixture expression; use a named builder")
			case *ast.CallExpr:
				// Runtime producers (for example an SSH harness's user lookup) are
				// outside this literal lint. Constructed ID strings must be resolvable.
				name := fixtureExprName(v.Fun)
				if name == "Sprintf" || name == "Repeat" || name == "Join" || name == "ReplaceAll" {
					report(n, "unsupported ID fixture expression; use a named builder")
				}
			}
			return
		}
		if !fixtureIDShape(value, prefix) {
			report(n, fmt.Sprintf("ID fixture %q must be %s plus 21 nanoid characters", value, prefix))
		}
	}
	var visitJSON func(ast.Expr, any, string)
	visitJSON = func(node ast.Expr, value any, parent string) {
		switch v := value.(type) {
		case map[string]any:
			for k, item := range v {
				if parent == "wrapped_keys" {
					if prefixes["usr_"] && !fixtureDynamicJSON(node, k) && !fixtureIDShape(k, "usr_") {
						report(node, "wrapped_keys fixture key must be a real-shaped usr_ ID")
					}
					continue
				}
				prefix := fixtureFieldPrefix(k, "")
				if k == "id" {
					if typ, _ := v["type"].(string); typ == "room_list" || typ == "room_added_to" {
						prefix = "room_"
					}
				}
				if s, ok := item.(string); ok && prefixes[prefix] && !(s == "" && fixtureOptionalEmpty(k, "")) && !fixtureDynamicJSON(node, s) && !fixtureIDShape(s, prefix) {
					report(node, fmt.Sprintf("JSON %s fixture %q must have %s shape", k, s, prefix))
				}
				if k == "members" || k == "admins" {
					if a, ok := item.([]any); ok && prefixes["usr_"] {
						for _, entry := range a {
							if s, ok := entry.(string); ok && !fixtureDynamicJSON(node, s) && !fixtureIDShape(s, "usr_") {
								report(node, "JSON member fixture must be a real-shaped usr_ ID")
							}
						}
					}
				}
				visitJSON(node, item, k)
			}
		case []any:
			for _, item := range v {
				visitJSON(node, item, parent)
			}
		}
	}
	var stack []ast.Node
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, node)
		if call, ok := node.(*ast.CallExpr); ok && fixtureBuilderPrefix(fixtureExprName(call.Fun)) != "" {
			stack = stack[:len(stack)-1]
			return false
		}
		if kv, ok := node.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && ast.IsExported(key.Name) {
				typ := ""
				if len(stack) > 1 {
					if c, ok := stack[len(stack)-2].(*ast.CompositeLit); ok {
						typ = fixtureExprName(c.Type)
						if c.Type == nil {
							for i := len(stack) - 3; i >= 0; i-- {
								if outer, ok := stack[i].(*ast.CompositeLit); ok {
									switch container := outer.Type.(type) {
									case *ast.ArrayType:
										typ = fixtureExprName(container.Elt)
									case *ast.MapType:
										typ = fixtureExprName(container.Value)
									}
									if typ != "" {
										break
									}
								}
							}
						}
					}
				}
				prefix := fixtureFieldPrefix(key.Name, typ)
				if typ == "ClientConfig" && key.Name == "User" {
					prefix = ""
				} // SSH login names are not application user IDs.
				if key.Name == "ID" && !fixtureMessageType(typ) {
					prefix = ""
				}
				value, known := fixtureString(kv.Value)
				if !(known && value == "" && fixtureOptionalEmpty(key.Name, typ)) {
					check(kv.Value, prefix)
				}
				if key.Name == "Members" || key.Name == "Admins" || key.Name == "FileIDs" {
					if list, ok := kv.Value.(*ast.CompositeLit); ok {
						p := "usr_"
						if key.Name == "FileIDs" {
							p = "file_"
						}
						for _, item := range list.Elts {
							check(item, p)
						}
					}
				}
				if key.Name == "WrappedKeys" {
					if m, ok := kv.Value.(*ast.CompositeLit); ok {
						for _, e := range m.Elts {
							if pair, ok := e.(*ast.KeyValueExpr); ok {
								check(pair.Key, "usr_")
							}
						}
					}
				}
			}
		}
		if a, ok := node.(*ast.AssignStmt); ok {
			for i, value := range a.Rhs {
				if i < len(a.Lhs) {
					check(value, fixtureVariablePrefix(fixtureExprName(a.Lhs[i])))
				}
			}
		}
		if a, ok := node.(*ast.ValueSpec); ok {
			for i, value := range a.Values {
				if i < len(a.Names) {
					check(value, fixtureVariablePrefix(a.Names[i].Name))
				}
			}
		}
		if call, ok := node.(*ast.CallExpr); ok {
			positions := map[string][]string{"CreateGroup": {"group_", "usr_"}, "CreateOrGetDirectMessage": {"dm_", "usr_", "usr_"}, "InsertUser": {"usr_"}, "RoomDB": {"room_"}, "GroupDB": {"group_"}, "DMDB": {"dm_"}}
			for i, prefix := range positions[fixtureExprName(call.Fun)] {
				if i < len(call.Args) {
					check(call.Args[i], prefix)
				}
			}
		}
		expr, ok := node.(ast.Expr)
		if !ok {
			return true
		}
		if len(stack) > 1 {
			switch parent := stack[len(stack)-2].(type) {
			case *ast.CallExpr:
				if fixtureExprName(parent.Fun) == "Sprintf" || fixtureExprName(parent.Fun) == "ReplaceAll" {
					return true
				}
			case *ast.Field:
				return true
			case *ast.BinaryExpr:
				if parent.Op == token.ADD {
					return true
				}
			}
		}
		switch value := expr.(type) {
		case *ast.BasicLit:
		case *ast.BinaryExpr:
			if value.Op != token.ADD {
				return true
			}
		case *ast.CallExpr:
			if fixtureExprName(value.Fun) != "Sprintf" && fixtureExprName(value.Fun) != "ReplaceAll" {
				return true
			}
		default:
			return true
		}
		value, known := fixtureJSONString(expr)
		if !known {
			return true
		}
		trimmed := strings.TrimSpace(value)
		if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
			return true
		}
		var decoded any
		if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			if (prefixes["room_"] && strings.Contains(value, `"room"`)) || (prefixes["group_"] && strings.Contains(value, `"group"`)) || (prefixes["file_"] && strings.Contains(value, `"file_id"`)) {
				report(expr, "unparseable JSON ID fixture; mark deliberate malformed input")
			}
			return true
		}
		visitJSON(expr, decoded, "")
		return true
	})
	return issues, nil
}

func fixtureExprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}
func fixtureBuilderPrefix(name string) string {
	return map[string]string{"DeviceID": "dev_", "UserID": "usr_", "MsgID": "msg_", "ReactionID": "react_", "RoomID": "room_", "GroupID": "group_", "DMID": "dm_", "FileID": "file_", "UploadID": "up_"}[name]
}
func fixtureVariablePrefix(name string) string {
	if !strings.HasSuffix(name, "ID") && !strings.HasSuffix(name, "Id") {
		return ""
	}
	return fixtureFieldPrefix(name, "")
}
func fixtureFieldPrefix(name, typ string) string {
	switch strings.ToLower(strings.ReplaceAll(name, "_", "")) {
	case "user", "userid", "sender", "from", "other", "actor", "actorid", "pinnedby", "deletedby", "generator":
		return "usr_"
	case "room", "roomid":
		return "room_"
	case "group", "groupid":
		return "group_"
	case "dm", "dmid":
		return "dm_"
	case "id":
		switch typ {
		case "User":
			return "usr_"
		case "Room", "RoomRecord":
			return "room_"
		case "Group", "GroupRecord":
			return "group_"
		case "DirectMessage":
			return "dm_"
		case "StoredFile":
			return "file_"
		default:
			return "msg_"
		}
	case "messageid", "msgid", "lastread", "before":
		return "msg_"
	case "reactionid":
		return "react_"
	case "fileid", "avatarid":
		return "file_"
	case "uploadid":
		return "up_"
	}
	return ""
}
func fixtureMessageType(typ string) bool {
	switch typ {
	case "StoredMessage", "Message", "GroupMessage", "DMMessage", "React", "Reaction", "Pin", "Pinned", "Unpin", "Unpinned", "Edit", "EditGroup", "EditDM", "Delete", "Deleted", "Edited", "GroupEdited", "DMEdited", "User", "Room", "RoomRecord", "Group", "GroupRecord", "DirectMessage", "StoredFile":
		return true
	}
	return false
}
func fixtureIDShape(value, prefix string) bool {
	if len(value) != len(prefix)+21 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, c := range value[len(prefix):] {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-", c) {
			return false
		}
	}
	return true
}
func fixtureString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			return s, err == nil
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			a, ok := fixtureString(v.X)
			b, ok2 := fixtureString(v.Y)
			return a + b, ok && ok2
		}
	case *ast.CallExpr:
		fn := fixtureExprName(v.Fun)
		if prefix := fixtureBuilderPrefix(fn); prefix != "" {
			return prefix + strings.Repeat("A", 21), true
		}
		if fn == "GenerateID" && len(v.Args) == 1 {
			prefix, ok := fixtureString(v.Args[0])
			return prefix + strings.Repeat("A", 21), ok
		}
		if fn == "GenerateRoomID" {
			return "room_" + strings.Repeat("A", 21), true
		}
		if fn == "Repeat" && len(v.Args) == 2 {
			a, ok := fixtureString(v.Args[0])
			n, ok2 := v.Args[1].(*ast.BasicLit)
			if ok && ok2 {
				count, err := strconv.Atoi(n.Value)
				if err == nil && count >= 0 && count <= 100000 {
					return strings.Repeat(a, count), true
				}
			}
		}
		if fn == "ReplaceAll" && len(v.Args) == 3 {
			a, ok := fixtureString(v.Args[0])
			b, ok2 := fixtureString(v.Args[1])
			c, ok3 := fixtureString(v.Args[2])
			return strings.ReplaceAll(a, b, c), ok && ok2 && ok3
		}
		if fn == "Sprintf" && len(v.Args) > 0 {
			format, ok := fixtureString(v.Args[0])
			if !ok {
				return "", false
			}
			args := []any{}
			for _, arg := range v.Args[1:] {
				if s, ok := fixtureString(arg); ok {
					args = append(args, s)
				} else if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.INT {
					n, err := strconv.Atoi(lit.Value)
					if err != nil {
						return "", false
					}
					args = append(args, n)
				} else {
					return fixtureFormatTemplate(format, v.Args[1:])
				}
			}
			return fmt.Sprintf(format, args...), true
		}
	}
	return "", false
}

// A runtime placeholder is not a literal ID: its producer remains covered
// by handler tests. Known literal arguments and static parts are still linted.
const fixtureDynamicMarker = "__FIXTURE_RUNTIME_VALUE__"

func fixtureDynamicJSON(node ast.Expr, value string) bool {
	if value != fixtureDynamicMarker {
		return false
	}
	return fixtureRuntimeExpression(node)
}
func fixtureRuntimeExpression(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.Ident, *ast.SelectorExpr:
		return true
	case *ast.BinaryExpr:
		return fixtureRuntimeExpression(value.X) || fixtureRuntimeExpression(value.Y)
	case *ast.CallExpr:
		if fixtureBuilderPrefix(fixtureExprName(value.Fun)) != "" {
			return false
		}
		for _, arg := range value.Args {
			if fixtureRuntimeExpression(arg) {
				return true
			}
		}
	}
	return false
}
func fixtureJSONString(expr ast.Expr) (string, bool) {
	if value, known := fixtureString(expr); known {
		return value, true
	}
	switch value := expr.(type) {
	case *ast.Ident, *ast.SelectorExpr:
		return fixtureDynamicMarker, true
	case *ast.BinaryExpr:
		if value.Op == token.ADD {
			a, ok := fixtureJSONString(value.X)
			b, ok2 := fixtureJSONString(value.Y)
			return a + b, ok && ok2
		}
	}
	return "", false
}

func fixtureFormatTemplate(format string, args []ast.Expr) (string, bool) {
	re := regexp.MustCompile(`%[-+# .0-9]*[a-zA-Z%]`)
	positions := re.FindAllStringIndex(format, -1)
	var out strings.Builder
	last, argIndex := 0, 0
	for _, position := range positions {
		out.WriteString(format[last:position[0]])
		spec := format[position[0]:position[1]]
		if spec == "%%" {
			out.WriteByte('%')
			last = position[1]
			continue
		}
		if argIndex >= len(args) {
			return "", false
		}
		arg := args[argIndex]
		argIndex++
		if value, ok := fixtureString(arg); ok {
			out.WriteString(fmt.Sprintf(spec, value))
		} else if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.INT {
			n, err := strconv.Atoi(lit.Value)
			if err != nil {
				return "", false
			}
			out.WriteString(fmt.Sprintf(spec, n))
		} else {
			quotes := 0
			escaped := false
			for _, c := range format[:position[0]] {
				if c == '"' && !escaped {
					quotes++
				}
				if c == '\\' && !escaped {
					escaped = true
				} else {
					escaped = false
				}
			}
			if quotes%2 == 1 {
				out.WriteString(fixtureDynamicMarker)
			} else {
				out.WriteString("null")
			}
		}
		last = position[1]
	}
	out.WriteString(format[last:])
	return out.String(), argIndex == len(args)
}

// Empty avatars clear a profile; empty read markers retain existing read
// semantics. Optional routed contexts are absent rather than malformed IDs.
func fixtureOptionalEmpty(field, typ string) bool {
	key := strings.ToLower(strings.ReplaceAll(field, "_", ""))
	if key == "avatarid" || key == "lastread" {
		return true
	}
	if key == "room" || key == "group" || key == "dm" {
		switch typ {
		case "Read", "Typing", "React", "Unreact", "Delete", "History", "StoredMessage":
			return true
		}
	}
	return false
}
