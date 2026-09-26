package storage

// Component is an object's content read together with its attributes.
type Component struct {
	content    []byte
	attributes map[string]string
}

func NewComponent(content []byte, attributes map[string]string) *Component {
	return &Component{content: content, attributes: attributes}
}

func (c *Component) GetContent() []byte               { return c.content }
func (c *Component) GetAttributes() map[string]string { return c.attributes }
