package scanner

// detectOS attempts to detect the operating system of the target
func (s *Scanner) detectOS() (string, int) {
	// Simplified OS detection based on open ports
	windowsPorts := []int{135, 139, 445, 3389}
	linuxPorts := []int{22, 111, 2049}

	windowsScore := 0
	linuxScore := 0

	for _, port := range windowsPorts {
		result := s.ScanPort("tcp", port)
		if result.State == "open" {
			windowsScore += 25
		}
	}

	for _, port := range linuxPorts {
		result := s.ScanPort("tcp", port)
		if result.State == "open" {
			linuxScore += 33
		}
	}

	if windowsScore > linuxScore {
		return "Windows", windowsScore
	} else if linuxScore > windowsScore {
		return "Linux", linuxScore
	}

	return "Unknown", 0
}
