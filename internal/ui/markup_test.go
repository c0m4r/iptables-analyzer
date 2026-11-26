package ui

import (
	"fmt"
	"regexp"
	"strings"
)

// The HTML report is written by one template, so its markup has a small,
// known vocabulary. The checks below read a page strictly against that
// vocabulary. Text from the analyzed rules that got out of a text node, in
// any way, would show as a tag, an attribute or a value that the template
// does not write.

type markupAttr struct{ name, value string }

type markupToken struct {
	// kind is "doctype", "open", "close", "text" or "raw" (the content of
	// the style and the script element).
	kind  string
	name  string
	attrs []markupAttr
	text  string
	// closed is true for an element written as <name/>.
	closed bool
}

func isNameByte(c byte, upper bool) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || (upper && c >= 'A' && c <= 'Z')
}

// scanMarkup splits a page into tags and text.
func scanMarkup(page string) ([]markupToken, error) {
	var tokens []markupToken
	for i := 0; i < len(page); {
		if page[i] != '<' {
			end := strings.IndexByte(page[i:], '<')
			if end < 0 {
				end = len(page) - i
			}
			text := page[i : i+end]
			if strings.ContainsRune(text, '>') {
				return nil, fmt.Errorf("text with a bare '>' at offset %d: %q", i, text)
			}
			tokens = append(tokens, markupToken{kind: "text", text: text})
			i += end
			continue
		}
		const doctype = "<!doctype html>"
		if strings.HasPrefix(page[i:], doctype) {
			tokens = append(tokens, markupToken{kind: "doctype"})
			i += len(doctype)
			continue
		}
		j := i + 1
		closing := j < len(page) && page[j] == '/'
		if closing {
			j++
		}
		start := j
		for j < len(page) && isNameByte(page[j], false) {
			j++
		}
		name := page[start:j]
		if name == "" {
			return nil, fmt.Errorf("'<' that starts no tag at offset %d: %q", i, excerpt(page, i))
		}
		if closing {
			if j >= len(page) || page[j] != '>' {
				return nil, fmt.Errorf("malformed closing tag at offset %d: %q", i, excerpt(page, i))
			}
			tokens = append(tokens, markupToken{kind: "close", name: name})
			i = j + 1
			continue
		}
		token := markupToken{kind: "open", name: name}
		for {
			for j < len(page) && (page[j] == ' ' || page[j] == '\n') {
				j++
			}
			if j >= len(page) {
				return nil, fmt.Errorf("tag without end at offset %d", i)
			}
			if page[j] == '>' {
				j++
				break
			}
			if strings.HasPrefix(page[j:], "/>") {
				token.closed = true
				j += 2
				break
			}
			start := j
			for j < len(page) && isNameByte(page[j], true) {
				j++
			}
			attr := markupAttr{name: page[start:j]}
			if attr.name == "" {
				return nil, fmt.Errorf("malformed attribute in <%s> at offset %d: %q", name, start, excerpt(page, start))
			}
			if strings.HasPrefix(page[j:], `="`) {
				end := strings.IndexByte(page[j+2:], '"')
				if end < 0 {
					return nil, fmt.Errorf("attribute value without end in <%s>", name)
				}
				attr.value = page[j+2 : j+2+end]
				j += 2 + end + 1
			} else if j < len(page) && page[j] == '=' {
				return nil, fmt.Errorf("attribute %s of <%s> has a value without quotes", attr.name, name)
			}
			token.attrs = append(token.attrs, attr)
		}
		tokens = append(tokens, token)
		i = j
		if name == "style" || name == "script" {
			end := strings.Index(page[i:], "</"+name+">")
			if end < 0 {
				return nil, fmt.Errorf("<%s> without end", name)
			}
			tokens = append(tokens, markupToken{kind: "raw", name: name, text: page[i : i+end]})
			i += end
		}
	}
	return tokens, nil
}

func excerpt(page string, at int) string {
	return page[at:min(len(page), at+60)]
}

var (
	pageTags = map[string]bool{}
	// voidTags have no closing tag.
	voidTags  = map[string]bool{"meta": true, "input": true}
	pageAttrs = map[string]bool{}

	anchorValue = regexp.MustCompile(`^[a-z0-9-]+$`)
	classValue  = regexp.MustCompile(`^[A-Za-z0-9 _-]*$`)
	// plainValue is what the template itself writes into the other
	// attributes. Escaped text from the input would hold a '&'.
	plainValue = regexp.MustCompile(`^[A-Za-z0-9 _.,:;=#/()'+-]*$`)
)

func init() {
	for _, name := range strings.Fields("html head meta title style body header div h1 h2 h3 h4 button nav a span main section svg rect " +
		"ol ul li p dl dt dd b small details summary code pre input table thead tbody tr th td footer script") {
		pageTags[name] = true
	}
	for _, name := range strings.Fields("lang charset http-equiv content name class id type href rel aria-label aria-live aria-pressed " +
		"placeholder open role viewBox preserveAspectRatio width height data-filter data-sev data-toggle data-state data-copy data-sort") {
		pageAttrs[name] = true
	}
}

// checkMarkup reports the first thing in a page that the template of the
// report does not write.
func checkMarkup(page string) error {
	tokens, err := scanMarkup(page)
	if err != nil {
		return err
	}
	if len(tokens) == 0 || tokens[0].kind != "doctype" {
		return fmt.Errorf("the page does not start with the doctype")
	}
	var stack []string
	ids := map[string]bool{}
	var links []string
	raw := map[string]int{}
	for _, token := range tokens {
		switch token.kind {
		case "raw":
			raw[token.name]++
			if want := map[string]string{"style": pageCSS, "script": pageJS}[token.name]; token.text != want {
				return fmt.Errorf("the <%s> element does not hold the %s of the report", token.name, token.name)
			}
		case "open":
			if !pageTags[token.name] {
				return fmt.Errorf("unknown element <%s>", token.name)
			}
			for _, attr := range token.attrs {
				if !pageAttrs[attr.name] {
					return fmt.Errorf("unknown attribute %s on <%s>", attr.name, token.name)
				}
				switch attr.name {
				case "id":
					if !anchorValue.MatchString(attr.value) {
						return fmt.Errorf("id %q is not made from a counter", attr.value)
					}
					if ids[attr.value] {
						return fmt.Errorf("id %q is used twice", attr.value)
					}
					ids[attr.value] = true
				case "href":
					switch {
					case attr.value == "https://github.com/c0m4r/iptables-analyzer":
					case strings.HasPrefix(attr.value, "#") && anchorValue.MatchString(attr.value[1:]):
						links = append(links, attr.value[1:])
					default:
						return fmt.Errorf("link to %q", attr.value)
					}
				case "class":
					if !classValue.MatchString(attr.value) {
						return fmt.Errorf("class %q", attr.value)
					}
				default:
					if !plainValue.MatchString(attr.value) {
						return fmt.Errorf("attribute %s=%q on <%s> holds what the template does not write", attr.name, attr.value, token.name)
					}
				}
			}
			if !voidTags[token.name] && !token.closed {
				stack = append(stack, token.name)
			}
		case "close":
			if len(stack) == 0 || stack[len(stack)-1] != token.name {
				return fmt.Errorf("</%s> does not close the open element (open: %v)", token.name, stack)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("elements left open: %v", stack)
	}
	if raw["style"] != 1 || raw["script"] != 1 {
		return fmt.Errorf("expected one style and one script element, got %d and %d", raw["style"], raw["script"])
	}
	for _, link := range links {
		if !ids[link] {
			return fmt.Errorf("link to #%s, which is not in the page", link)
		}
	}
	return nil
}

// skeleton renders the tags of a page with their attributes and without the
// text, so that two pages can be compared for their structure.
func skeleton(page string) (string, error) {
	tokens, err := scanMarkup(page)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, token := range tokens {
		switch token.kind {
		case "open":
			out.WriteString("<" + token.name)
			for _, attr := range token.attrs {
				fmt.Fprintf(&out, " %s=%q", attr.name, attr.value)
			}
			out.WriteString(">\n")
		case "close":
			out.WriteString("</" + token.name + ">\n")
		}
	}
	return out.String(), nil
}
