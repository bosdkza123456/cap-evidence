package genericjson

import (
	"capevidence/internal/model"
	"capevidence/internal/parse"
	"capevidence/internal/validate"
)

func Parse(input []byte, lim model.Limits) (model.Bundle, []model.Diagnostic, error) {
	var b model.Bundle
	if e := parse.Decode(input, "json", &b, lim); e != nil {
		return model.Bundle{}, nil, e
	}
	if e := validate.Bundle(b, lim); e != nil {
		return model.Bundle{}, nil, e
	}
	return b, []model.Diagnostic{}, nil
}
