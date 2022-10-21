package parsing

import "regexp"

func NamedSubexps(re *regexp.Regexp, input string) map[string]string {
	output := make(map[string]string)
	matches := re.FindStringSubmatch(input)

	for _, name := range re.SubexpNames() {
		index := re.SubexpIndex(name)

		if index < 1 {
			continue
		}

		output[name] = matches[index]
	}

	return output
}
