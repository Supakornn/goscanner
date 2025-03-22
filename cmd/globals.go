package cmd

// returns true if verbose is enabled
func IsVerbose() bool {
	return verbose
}

// returns true if showFiltered is enabled
func ShouldShowFiltered() bool {
	return showFiltered
}

// returns the output file
func GetOutputFile() string {
	return outputFile
}

// returns the output format
func GetOutputFormat() string {
	return outputFormat
}

// returns the specific ports
func GetSpecificPorts() string {
	return specificPorts
}
