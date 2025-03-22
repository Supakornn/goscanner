package cmd

func IsVerbose() bool {
	return verbose
}

func ShouldShowFiltered() bool {
	return showFiltered
}

func GetOutputFile() string {
	return outputFile
}

func GetOutputFormat() string {
	return outputFormat
}

func GetSpecificPorts() string {
	return specificPorts
}
