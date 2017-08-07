package metrics

// Aggregation Spec serialization

type AggregationSpec struct {
	Channels []Channel   `json:"channels" yaml:"channels"`
	Events   []EventSpec `json:"events" yaml:"events"`
}

type Channel struct {
	Id   string `json:"id" yaml:"id"`
	Type string `json:"type" yaml:"type"`
	Path string `json:"path" yaml:"path"`
}

type EventSpec struct {
	Name      string   `json:"name" yaml:"name"`
	ChannelId string   `json:"channel" yaml:"channel"`
	Stream    string   `json:"stream" yaml:"stream"`
	Group     string   `json:"group" yaml:"group"`
	Rule      string   `json:"rule" yaml:"rule"`
	F         Function `json:"function" yaml:"function"`
	O         Output   `json:"output" yaml:"output"`
}

type Function struct {
	Id         string `json:"id" yaml:"id"`
	Parameters string `json:"parameters" yaml:"parameters"`
	state      processingFunc
}

type Output struct {
	Metrics string `json:"metrics" yaml:"metrics"`
	Format  string `json:"format" yaml:"format"`
	state   outputFunc
}
