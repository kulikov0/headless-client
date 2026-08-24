package headlessclient

import (
	"strconv"
	"strings"
)

var greasedBrandSeparators = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}

var greasedBrandVersions = []string{"8", "99", "24"}

var brandShufflePermutations = [][]int{
	{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0},
}

type brandVersion struct {
	brand   string
	version string
}

func greasedBrandVersion(majorVersion int) brandVersion {
	firstSeparator := greasedBrandSeparators[majorVersion%len(greasedBrandSeparators)]
	secondSeparator := greasedBrandSeparators[(majorVersion+1)%len(greasedBrandSeparators)]

	return brandVersion{
		brand:   "Not" + firstSeparator + "A" + secondSeparator + "Brand",
		version: greasedBrandVersions[majorVersion%len(greasedBrandVersions)],
	}
}

func shuffleBrandVersions(brands []brandVersion, majorVersion int) []brandVersion {
	permutation := brandShufflePermutations[majorVersion%len(brandShufflePermutations)]
	if len(brands) == 2 {
		permutation = []int{majorVersion % 2, (majorVersion + 1) % 2}
	}

	shuffled := make([]brandVersion, len(brands))
	for index, position := range permutation {
		shuffled[position] = brands[index]
	}

	return shuffled
}

func clientHintBrandList(majorVersion int, productBrand string) string {
	version := strconv.Itoa(majorVersion)
	brands := []brandVersion{greasedBrandVersion(majorVersion), {brand: "Chromium", version: version}}
	if productBrand != "" {
		brands = append(brands, brandVersion{brand: productBrand, version: version})
	}

	formatted := make([]string, 0, len(brands))
	for _, entry := range shuffleBrandVersions(brands, majorVersion) {
		formatted = append(formatted, `"`+entry.brand+`";v="`+entry.version+`"`)
	}

	return strings.Join(formatted, ", ")
}
