package apps

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	log "github.com/sirupsen/logrus"
	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater/fetchers/ubuntu"
	"google.golang.org/protobuf/encoding/protojson"
)

const goVulnDBPath = "apps/golang-osv.zip"

// SetUbuntuSeverityMap sets the Ubuntu severity mapping from external source
func SetUbuntuVulnerabilityMap(ubuntuVulnerabilities []common.Vulnerability) map[string]common.Vulnerability {

	var ubuntuVulnerabilityMap = make(map[string]common.Vulnerability)
	for _, vulnerability := range ubuntuVulnerabilities {
		if vulnerability.Name == "CVE-2025-47909" {
			fmt.Println(vulnerability)
		}
		ubuntuVulnerabilityMap[vulnerability.Name] = vulnerability
	}
	return ubuntuVulnerabilityMap
}

// // Parse all OSV files from local vulndb
// func parseGoOSVFiles(vulndbPath string) ([]*common.AppModuleVul, error) {
// 	osvPath := filepath.Join(vulndbPath, "data", "osv")

// 	files, err := filepath.Glob(filepath.Join(osvPath, "GO-*.json"))
// 	if err != nil {
// 		return nil, err
// 	}

// 	log.WithFields(log.Fields{"count": len(files), "path": osvPath}).Info("Found Go OSV files")

// 	var vulnerabilities []*common.AppModuleVul
// 	successCount := 0
// 	errorCount := 0

// 	for _, file := range files {
// 		data, err := ioutil.ReadFile(file)
// 		if err != nil {
// 			log.WithFields(log.Fields{"file": filepath.Base(file), "error": err}).Warn("Failed to read OSV file")
// 			errorCount++
// 			continue
// 		}

// 		var osv osvschema.Vulnerability
// 		if err := json.Unmarshal(data, &osv); err != nil {
// 			log.WithFields(log.Fields{"file": filepath.Base(file), "error": err}).Warn("Failed to parse OSV JSON")
// 			errorCount++
// 			continue
// 		}

// 		// Convert OSV to AppModuleVul
// 		appVuls := osvToAppModuleVul(&osv)
// 		for _, appVul := range appVuls {
// 			if appVul != nil {
// 				vulnerabilities = append(vulnerabilities, appVul)
// 				successCount++
// 			}
// 		}

// 	}

// 	log.WithFields(log.Fields{
// 		"total":   len(files),
// 		"success": successCount,
// 		"errors":  errorCount,
// 		"vulns":   len(vulnerabilities),
// 	}).Info("Parsed Go vulnerabilities")

// 	return vulnerabilities, nil
// }

// // Convert OSV entry to AppModuleVul (can return multiple if multiple packages affected)
// func osvToAppModuleVul(osv *OSVEntry) []*common.AppModuleVul {
// 	if len(osv.Affected) == 0 {
// 		return nil
// 	}

// 	var result []*common.AppModuleVul

// 	// remove temporary debug logs
// 	// Process each affected package (Go vulns can affect multiple packages)
// 	for _, affected := range osv.Affected {
// 		appVul := &common.AppModuleVul{
// 			VulName:     osv.ID,
// 			AppName:     "go",
// 			ModuleName:  "go:" + affected.Package.Name,
// 			Description: osv.Details,
// 			IssuedDate:  osv.Published,
// 			LastModDate: osv.Modified,
// 			CVEs:        make([]string, 0),
// 			FixedVer:    make([]common.AppModuleVersion, 0),
// 			AffectedVer: make([]common.AppModuleVersion, 0),
// 		}

// 		// Use summary if details is empty
// 		if appVul.Description == "" {
// 			appVul.Description = osv.Summary
// 		}

// 		// Extract CVEs from aliases
// 		for _, alias := range osv.Aliases {
// 			if strings.HasPrefix(alias, "CVE-") {
// 				appVul.CVEs = append(appVul.CVEs, alias)
// 			}
// 		}

// 		// Find reference link (prefer ADVISORY, then WEB, then any)
// 		for _, ref := range osv.References {
// 			if ref.Type == "ADVISORY" {
// 				appVul.Link = ref.URL
// 				break
// 			}
// 		}
// 		if appVul.Link == "" {
// 			for _, ref := range osv.References {
// 				if ref.Type == "WEB" || ref.Type == "REPORT" {
// 					appVul.Link = ref.URL
// 					break
// 				}
// 			}
// 		}
// 		if appVul.Link == "" && len(osv.References) > 0 {
// 			appVul.Link = osv.References[0].URL
// 		}

// 		// Parse severity from database_specific
// 		if severity, ok := osv.DatabaseSpecific["severity"].(string); ok {
// 			appVul.Severity = parseSeverity(severity)
// 		} else {
// 			// Default to Unknown if not specified
// 			appVul.Severity = common.Unknown
// 		}

// 		// Parse CVSS scores if available
// 		if cvss, ok := osv.DatabaseSpecific["cvss"].(map[string]interface{}); ok {
// 			if score, ok := cvss["score"].(float64); ok {
// 				appVul.ScoreV3 = score
// 			}
// 			if vector, ok := cvss["vector"].(string); ok {
// 				appVul.VectorsV3 = vector
// 			}
// 		}

// 		// Parse version ranges (SEMVER)
// 		for _, r := range affected.Ranges {
// 			if r.Type != "SEMVER" {
// 				continue
// 			}

// 			for _, event := range r.Events {
// 				if event.Introduced != "" {
// 					appVul.AffectedVer = append(appVul.AffectedVer, common.AppModuleVersion{
// 						OpCode:  "gteq",
// 						Version: event.Introduced,
// 					})
// 				}

// 				if event.Fixed != "" {
// 					// Also add to affected as upper bound
// 					appVul.AffectedVer = append(appVul.AffectedVer, common.AppModuleVersion{
// 						OpCode:  "lt",
// 						Version: event.Fixed,
// 					})
// 				}
// 			}
// 		}

// 		result = append(result, appVul)
// 	}

// 	return result
// }

// func parseSeverity(s string) common.Priority {
// 	switch strings.ToUpper(s) {
// 	case "CRITICAL":
// 		return common.Critical
// 	case "HIGH":
// 		return common.High
// 	case "MEDIUM":
// 		return common.Medium
// 	case "LOW":
// 		return common.Low
// 	default:
// 		return common.Unknown
// 	}
// }

// func parseGoOSVFiles(vulndbPath string) ([]*common.AppModuleVul, error) {
// 	osvPath := filepath.Join(vulndbPath, "data", "osv")
// }

// func loadZipFile(zipFile *zip.File) {
// 	file, err := zipFile.Open()
// 	if err != nil {
// 		log.Warnf("Could not read %s: %v", zipFile.Name, err)

// 		return
// 	}
// 	defer file.Close()

// 	content, err := io.ReadAll(file)
// 	if err != nil {
// 		log.Warnf("Could not read %s: %v", zipFile.Name, err)
// 		return
// 	}

// 	var vulnerability osvschema.Vulnerability

// 	if err := json.Unmarshal(content, &vulnerability); err != nil {
// 		log.Warnf("%s is not a valid JSON file: %v", zipFile.Name, err)

// 		// return
// 	}

// 	println(vulnerability.Id)
// }

func loadZipFile(zipFile *zip.File) (error, *osvschema.Vulnerability) {
	file, err := zipFile.Open()
	if err != nil {
		log.Warnf("Could not read %s: %v", zipFile.Name, err)
		return err, nil
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		log.Warnf("Could not read %s: %v", zipFile.Name, err)
		return err, nil
	}

	var vulnerability osvschema.Vulnerability

	if err := protojson.Unmarshal(content, &vulnerability); err != nil {
		log.Warnf("%s is not a valid JSON file: %v", zipFile.Name, err)
		return err, nil
	}
	return nil, &vulnerability
}

func getUrl(vulnerability *osvschema.Vulnerability) string {
	link := ""

	if vulnerability.DatabaseSpecific != nil {
		fields := vulnerability.DatabaseSpecific.GetFields()

		if urlField, ok := fields["url"]; ok {
			link = urlField.GetStringValue()
		}
	}

	if link == "" {
		for _, ref := range vulnerability.References {
			link = ref.Url
			break
		}
	}

	return link
}

// getSeverityLevel follow the neuvector severity mapping
func getSeverityLevel(score string) common.Priority {

	return common.Critical
}

// getSeverity gets severity from OSV database_specific or Ubuntu mapping
func getSeverity(appVul *common.AppModuleVul, ubuntuVulnerabilityMap map[string]common.Vulnerability, vulnerability *osvschema.Vulnerability) {
	// go OSV does not support the severity, only support the score. https://go.dev/doc/security/vuln/
	// if len(vulnerability.Severity) > 0 {
	// 	// get the first severity
	// 	severity := vulnerability.Severity[0].Severity
	// 	score := vulnerability.Severity[0].Score
	// 	if severity == "CRITICAL" {
	// 		appVul.Severity = common.Critical
	// 	} else if severity == "HIGH" {
	// 		appVul.Severity = common.High
	// 	} else if severity == "MEDIUM" {
	// 		appVul.Severity = common.Medium
	// 	} else if severity == "LOW" {
	// 	appVul.Severity = getSeverityLevel(score)
	// 	return
	// }

	// Use the Ubuntu severity mapping
	if ubuntuVulnerabilityMap == nil {
		return
	}

	for _, alias := range vulnerability.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			if ubuntuVulnerability, ok := ubuntuVulnerabilityMap[alias]; ok {
				appVul.VulName = ubuntuVulnerability.Name
				appVul.Severity = ubuntuVulnerability.Severity
				appVul.Score = ubuntuVulnerability.CVSSv2.Score
				appVul.Vectors = ubuntuVulnerability.CVSSv2.Vectors
				appVul.ScoreV3 = ubuntuVulnerability.CVSSv3.Score
				appVul.VectorsV3 = ubuntuVulnerability.CVSSv3.Vectors
				appVul.Link = ubuntuVulnerability.Link
				return
			}
		}
	}
}

// convertGoOSVToAppModuleVul converts a Go OSV vulnerability to an AppModuleVul
// Since most of the vulnerabiltity has no severity, we need to use the Ubuntu severity mapping
func convertGoOSVToAppModuleVul(vulnerability *osvschema.Vulnerability, ubuntuVulnerabilityMap map[string]common.Vulnerability) {
	for _, affected := range vulnerability.Affected {
		appVul := &common.AppModuleVul{
			VulName:     vulnerability.Id,
			AppName:     "go",
			ModuleName:  "go:" + affected.Package.Name,
			Description: vulnerability.Details,
			IssuedDate:  vulnerability.Published.AsTime(),
			LastModDate: vulnerability.Modified.AsTime(),
			CVEs:        make([]string, 0),
			FixedVer:    make([]common.AppModuleVersion, 0),
			AffectedVer: make([]common.AppModuleVersion, 0),
			Link:        getUrl(vulnerability),
		}

		// Fill severity if present in database_specific; otherwise leave Unknown
		// getSeverity(appVul, ubuntuSeverityMap, vulnerability)
		if vulnerability.Severity != nil {
			fmt.Println(vulnerability.Severity)
		}

		getSeverity(appVul, ubuntuVulnerabilityMap, vulnerability)

		if vulnerability.Id == "GO-2025-3849" {
			fmt.Println(appVul)
		}

		if appVul.Description == "" {
			appVul.Description = vulnerability.Summary
		}

		// Extract CVEs from aliases
		for _, alias := range vulnerability.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				appVul.CVEs = append(appVul.CVEs, alias)
			}
		}
		// Parse version ranges (SEMVER)
		for _, r := range affected.Ranges {
			if r.Type != osvschema.Range_SEMVER {
				continue
			}

			for _, event := range r.Events {
				if event.Introduced != "" {
					appVul.AffectedVer = append(appVul.AffectedVer, common.AppModuleVersion{
						OpCode:  "gteq",
						Version: event.Introduced,
					})
				}

				if event.Fixed != "" {
					appVul.AffectedVer = append(appVul.AffectedVer, common.AppModuleVersion{
						OpCode:  "lt",
						Version: event.Fixed,
					})
				}
			}
		}
	}
}

// Main update function - integrates into your existing flow
func govulnUpdate() error {
	log.Info("Starting Go vulnerability update...")
	ubuntuFetcher := ubuntu.UbuntuFetcher{}
	response, err := ubuntuFetcher.FetchUpdate()
	if err != nil {
		return err
	}

	var ubuntuVulnerabilityMap map[string]common.Vulnerability
	ubuntuVulnerabilityMap = SetUbuntuVulnerabilityMap(response.Vulnerabilities)

	dataFile := fmt.Sprintf("%s%s", common.CVESourceRoot, goVulnDBPath)
	zipReader, err := zip.OpenReader(dataFile)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {

		err, vulnerability := loadZipFile(file)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to load Go OSV file")
			return err
		}
		convertGoOSVToAppModuleVul(vulnerability, ubuntuVulnerabilityMap)
	}
	// Parse OSV files
	// vulnerabilities, err := parseGoOSVFiles(goVulnDBPath)
	// if err != nil {
	// 	log.WithFields(log.Fields{"error": err}).Error("Failed to parse Go OSV files")
	// 	return err
	// }

	// // Add to vulMap (your existing global map)
	// for _, mv := range vulnerabilities {
	// 	// Skip if already in cache
	// 	cacheKey := fmt.Sprintf("go:%s:%s", mv.ModuleName, mv.VulName)
	// 	if vulCache.Contains(cacheKey) {
	// 		continue
	// 	}
	// 	vulCache.Add(cacheKey)

	// 	// Add to vulMap with proper key
	// 	addAppVulMap(mv)
	// }

	// log.WithFields(log.Fields{
	// 	"vulnerabilities": len(vulnerabilities),
	// }).Info("Go vulnerability update completed")

	return nil
}
