package analyzer

import (
	"sort"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

func sortedTableNames(rs *models.Ruleset) []string {
	names := make([]string, 0, len(rs.Tables))
	for name := range rs.Tables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedChainNames(table *models.Table) []string {
	names := make([]string, 0, len(table.Chains))
	for name := range table.Chains {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
