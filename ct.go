package certool

type Certool struct{}

func NewCertool() Certool {
	return Certool{}
}

func (ct *Certool) NewKey() {
}

func (ct *Certool) toPem() {
}
