package core

import (
	"fmt"

	"github.com/crillab/gophersat/solver"
)

// VaultKeySatSolver manages the SAT-based search for valid Vault unseal key combinations.
// It uses pure CNF (Conjunctive Normal Form) encoding for all constraints and incremental
// solving to systematically explore combinations while learning from failures.
//
// Problem formulation:
// - Variables: x_i in {0,1} for each candidate key i (1: real key, 0: fake key)
// - Constraints (all in CNF):
//  1. Exactly 'threshold' keys must be selected (encoded via Sequential Counter)
//     - {x_1, ..., x_j} where j = threshold
//  2. After each failed test: at least one key in the tested set must be fake
//     - Sum(x_j) < threshold
//  3. After failed test with invalid key (i.e. vault states x_i is invalid format),
//     that key must be fake
//     - x_i = 0 for invalid key i
//
// The solver iteratively:
// 1. Builds complete CNF formula from all constraints
// 2. Solves to find a satisfying assignment
// 3. Tests those keys with Vault
// 4. If failure, adds "at least one is fake" clause
// 5. If success or UNSAT (Unsatisfiable), terminates
type VaultKeySatSolver struct {
	keyVars        []int   // SAT variable for each candidate key (1-indexed)
	numKeys        int     // Total number of candidate keys (N)
	threshold      int     // Minimum keys needed to unseal (Shamir threshold, m)
	totalKeys      int     // Total number of real keys in existence (M), -1 if unknown
	failureClauses [][]int // Clauses from failed tests (each: at least one tested key is fake)
	auxVarCounter  int     // Counter for auxiliary variables used in encoding

	// Stat
	attemptCount int     // Number of Vault test attempts
	testedSets   [][]int // History of tested key index sets (for debugging)
}

// NewVaultKeySatSolver creates a new SAT solver for finding valid Vault unseal key combinations.
func NewVaultKeySatSolver(numKeys, threshold, totalKeys int) *VaultKeySatSolver {
	// Allocate variables for each key (gophersat uses 1-indexed variables)
	keyVars := make([]int, numKeys)
	for i := range numKeys {
		keyVars[i] = i + 1
	}

	return &VaultKeySatSolver{
		keyVars:        keyVars,
		numKeys:        numKeys,
		threshold:      threshold,
		totalKeys:      totalKeys,
		failureClauses: [][]int{},
		testedSets:     make([][]int, 0),
	}
}

// encodeExactlyK generates CNF clauses encoding "exactly K of the given variables are true".
// Uses direct binomial encoding: simple and correct for small N and K.
func (vs *VaultKeySatSolver) encodeExactlyK(vars []int, k int) [][]int {
	n := len(vars)
	// when we have to select more than what we have, or we have to select less than 0
	if k > n || k < 0 {
		return [][]int{{}} // Empty clause = UNSAT (Unsatisfiable)
	}
	if k == 0 {
		// All must be false
		clauses := make([][]int, n)
		for i, v := range vars {
			clauses[i] = []int{-v}
		}
		return clauses
	}
	if k == n {
		// All must be true
		clauses := make([][]int, n)
		for i, v := range vars {
			clauses[i] = []int{v}
		}
		return clauses
	}

	clauses := [][]int{}

	// Part 1: "At most k" - for every subset of (k+1) variables, at least one must be false
	// This prevents having more than k variables true
	vs.generateAtMostKClauses(vars, k, &clauses)

	// Part 2: "At least k" - for every subset of (n-k+1) variables, at least one must be true
	// This ensures we have at least k variables true
	vs.generateAtLeastKClauses(vars, k, &clauses)

	return clauses
}

// generateAtMostKClauses generates clauses for "at most k variables can be true"
// For each subset of size (k+1), add clause: at least one must be false
func (vs *VaultKeySatSolver) generateAtMostKClauses(vars []int, k int, clauses *[][]int) {
	n := len(vars)
	// Generate all (k+1)-sized subsets
	vs.generateCombinations(n, k+1, func(indices []int) {
		clause := make([]int, k+1)
		for i, idx := range indices {
			clause[i] = -vars[idx] // At least one must be FALSE
		}
		*clauses = append(*clauses, clause)
	})
}

// generateAtLeastKClauses generates clauses for "at least k variables must be true"
// For each subset of size (n-k+1), add clause: at least one must be true
func (vs *VaultKeySatSolver) generateAtLeastKClauses(vars []int, k int, clauses *[][]int) {
	n := len(vars)
	// Generate all (n-k+1)-sized subsets
	vs.generateCombinations(n, n-k+1, func(indices []int) {
		clause := make([]int, n-k+1)
		for i, idx := range indices {
			clause[i] = vars[idx] // At least one must be TRUE
		}
		*clauses = append(*clauses, clause)
	})
}

// generateCombinations generates all k-sized combinations from [0..n-1] and calls callback for each
func (vs *VaultKeySatSolver) generateCombinations(n, k int, callback func([]int)) {
	combination := make([]int, k)
	var generate func(start, depth int)
	generate = func(start, depth int) {
		if depth == k {
			callback(combination)
			return
		}
		for i := start; i <= n-(k-depth); i++ {
			combination[depth] = i
			generate(i+1, depth+1)
		}
	}
	generate(0, 0)
}

// encodeAtMostK generates CNF clauses encoding "at most K of the given variables are true".
// Uses Sequential Counter encoding with O(N*K) auxiliary variables.
func (vs *VaultKeySatSolver) encodeAtMostK(vars []int, k int) [][]int {
	n := len(vars)
	if k >= n {
		// Always satisfiable, no constraints needed
		return [][]int{}
	}
	if k < 0 {
		// Unsatisfiable
		return [][]int{{}}
	}

	clauses := [][]int{}

	// Allocate auxiliary variables
	// Note: we need fresh variables for each call, so use a counter
	baseVar := vs.numKeys + 1 + vs.auxVarCounter
	vs.auxVarCounter += (n - 1) * k

	s := make([][]int, n-1)
	for i := 0; i < n-1; i++ {
		s[i] = make([]int, k+1)
		for j := 1; j <= k; j++ {
			s[i][j] = baseVar
			baseVar++
		}
	}

	// Clause for first variable (i=0)
	// vars[0] → s[0][1]
	clauses = append(clauses, []int{-vars[0], s[0][1]})

	// Clauses for i=1..(n-2)
	for i := 1; i < n-1; i++ {
		vi := vars[i]

		// vi → s[i][1]
		clauses = append(clauses, []int{-vi, s[i][1]})

		// s[i-1][k] → ¬vi (prevent exceeding k)
		clauses = append(clauses, []int{-s[i-1][k], -vi})

		// Propagation clauses
		for j := 1; j <= k; j++ {
			// s[i-1][j] → s[i][j]
			clauses = append(clauses, []int{-s[i-1][j], s[i][j]})

			if j >= 2 {
				// s[i-1][j-1] ∧ vi → s[i][j]
				clauses = append(clauses, []int{-s[i-1][j-1], -vi, s[i][j]})
			}
		}
	}

	// Final constraint for last variable
	vn := vars[n-1]
	// s[n-2][k] → ¬vn (prevent exceeding k)
	clauses = append(clauses, []int{-s[n-2][k], -vn})

	return clauses
}

// GetNextKeyCombination queries the SAT solver for the next combination of keys to test.
// resulting key indices are 0-indexed.
func (vs *VaultKeySatSolver) GetNextKeyCombination() ([]int, error) {
	// Reset auxiliary variable counter for fresh encoding
	vs.auxVarCounter = 0

	// Build complete CNF formula
	allClauses := [][]int{}

	// Add constraint: exactly 'threshold' amount of all keys must be selected
	exactlyThresholdClauses := vs.encodeExactlyK(vs.keyVars, vs.threshold)
	allClauses = append(allClauses, exactlyThresholdClauses...)

	// Add all failure clauses
	allClauses = append(allClauses, vs.failureClauses...)

	// Create Problem and solve
	pb := solver.ParseSlice(allClauses)
	s := solver.New(pb)

	if s.Solve() != solver.Sat {
		return nil, fmt.Errorf("no valid key combination exists (UNSAT after %d attempts)", vs.attemptCount)
	}

	// Extract solution
	model := s.Model()
	trueKeys := []int{}
	for i := 0; i < vs.numKeys; i++ {
		varID := vs.keyVars[i] // 1-indexed variable ID
		// Model is 0-indexed: model[0] = var 1, model[1] = var 2, etc.
		if varID-1 < len(model) && model[varID-1] {
			trueKeys = append(trueKeys, i)
		}
	}

	// assert the number of true keys matches the threshold
	if len(trueKeys) != vs.threshold {
		return nil, fmt.Errorf("internal error: solver returned %d keys, expected %d", len(trueKeys), vs.threshold)
	}

	// Record attempt
	vs.attemptCount++
	vs.testedSets = append(vs.testedSets, append([]int(nil), trueKeys...))

	return trueKeys, nil
}

// BackboneResult contains the results of backbone computation
type BackboneResult struct {
	DefinitelyReal  []int // Key indices that must be real (true in all models)
	DefinitelyFake  []int // Key indices that must be fake (false in all models)
	Undetermined    []int // Key indices that could be either
	MaxSatisfiable  int   // Maximum number of keys that can be true (for UNSAT case)
}

// ComputeBackbone analyzes fixed variable assignments after the search completes.
// If foundSolution is true, successfulKeys contains the indices of keys that unsealed the vault.
// Returns classification of all keys based on learned constraints.
func (vs *VaultKeySatSolver) ComputeBackbone(foundSolution bool, successfulKeys []int) (*BackboneResult, error) {
	result := &BackboneResult{
		DefinitelyReal: []int{},
		DefinitelyFake: []int{},
		Undetermined:   []int{},
	}

	if foundSolution {
		// Case 1: We found a valid solution that unsealed the vault
		// The successful keys are definitely real
		result.DefinitelyReal = append(result.DefinitelyReal, successfulKeys...)

		// For other keys, check if they can be true given the constraints
		successSet := make(map[int]bool)
		for _, k := range successfulKeys {
			successSet[k] = true
		}

		for i := 0; i < vs.numKeys; i++ {
			if successSet[i] {
				continue // Already classified as real
			}

			// Test if this key can be true
			vs.auxVarCounter = 0
			allClauses := [][]int{}

			// Add failure clauses
			allClauses = append(allClauses, vs.failureClauses...)

			// Add "exactly threshold" constraint
			exactlyThresholdClauses := vs.encodeExactlyK(vs.keyVars, vs.threshold)
			allClauses = append(allClauses, exactlyThresholdClauses...)

			// Force this variable to be true
			allClauses = append(allClauses, []int{vs.keyVars[i]})

			pb := solver.ParseSlice(allClauses)
			s := solver.New(pb)

			if s.Solve() != solver.Sat {
				// If forcing it true causes UNSAT, it must be false
				result.DefinitelyFake = append(result.DefinitelyFake, i)
			} else {
				// Could be either true or false
				result.Undetermined = append(result.Undetermined, i)
			}
		}
	} else {
		// Case 2: No valid solution exists (UNSAT with exactly threshold keys)
		// Find the maximum satisfiable set of keys

		// Binary search for maximum satisfiable k
		left, right := 0, vs.threshold-1
		maxK := 0
		var maxModel []bool

		for left <= right {
			mid := (left + right) / 2

			vs.auxVarCounter = 0
			allClauses := [][]int{}

			// Add failure clauses
			allClauses = append(allClauses, vs.failureClauses...)

			// Try "exactly mid" keys
			if mid > 0 {
				exactlyMidClauses := vs.encodeExactlyK(vs.keyVars, mid)
				allClauses = append(allClauses, exactlyMidClauses...)
			}

			pb := solver.ParseSlice(allClauses)
			s := solver.New(pb)

			if s.Solve() == solver.Sat {
				// Found satisfiable with mid keys
				maxK = mid
				maxModel = s.Model()
				left = mid + 1
			} else {
				// Not satisfiable with mid keys
				right = mid - 1
			}
		}

		result.MaxSatisfiable = maxK

		// Extract the maximum satisfiable set
		maxSatKeys := []int{}
		if maxModel != nil {
			for i := 0; i < vs.numKeys; i++ {
				varID := vs.keyVars[i]
				if varID-1 < len(maxModel) && maxModel[varID-1] {
					maxSatKeys = append(maxSatKeys, i)
				}
			}
		}

		// Now perform backbone computation with max satisfiable constraint
		for i := 0; i < vs.numKeys; i++ {
			isInMaxSet := false
			for _, k := range maxSatKeys {
				if k == i {
					isInMaxSet = true
					break
				}
			}

			// Test if forcing this variable to true maintains max satisfiability
			vs.auxVarCounter = 0
			allClauses := [][]int{}

			// Add failure clauses
			allClauses = append(allClauses, vs.failureClauses...)

			if maxK > 0 {
				// Add "exactly maxK" constraint
				exactlyMaxClauses := vs.encodeExactlyK(vs.keyVars, maxK)
				allClauses = append(allClauses, exactlyMaxClauses...)
			}

			if !isInMaxSet {
				// Force this variable to be true
				allClauses = append(allClauses, []int{vs.keyVars[i]})

				pb := solver.ParseSlice(allClauses)
				s := solver.New(pb)

				if s.Solve() != solver.Sat {
					// Cannot be true while maintaining max satisfiability
					result.DefinitelyFake = append(result.DefinitelyFake, i)
					continue
				}
			}

			// Test if forcing this variable to false maintains max satisfiability
			vs.auxVarCounter = 0
			allClauses = [][]int{}

			// Add failure clauses
			allClauses = append(allClauses, vs.failureClauses...)

			if maxK > 0 {
				// Add "exactly maxK" constraint
				exactlyMaxClauses := vs.encodeExactlyK(vs.keyVars, maxK)
				allClauses = append(allClauses, exactlyMaxClauses...)
			}

			// Force this variable to be false
			allClauses = append(allClauses, []int{-vs.keyVars[i]})

			pb := solver.ParseSlice(allClauses)
			s := solver.New(pb)

			if s.Solve() != solver.Sat {
				// Cannot be false while maintaining max satisfiability - must be true
				result.DefinitelyReal = append(result.DefinitelyReal, i)
			} else {
				// Can be either true or false (even if in max set, can be replaced)
				result.Undetermined = append(result.Undetermined, i)
			}
		}
	}

	return result, nil
}

// RecordFailure records a failed Vault unseal attempt and adds a CNF clause.
// Clause: -v_1 + -v_2 + ... + -v_n means "at least one of the tested keys is fake".
// keyIndices are 0-indexed.
func (vs *VaultKeySatSolver) RecordFailure(keyIndices []int) {
	clause := make([]int, len(keyIndices))
	for i, keyIdx := range keyIndices {
		clause[i] = -vs.keyVars[keyIdx]
	}

	vs.failureClauses = append(vs.failureClauses, clause)
}

// RecordFalseKey records a fake Vault unseal attempt and adds a CNF clause.
// Cluase: -v_i means "the i-th key is fake".
// keyIndex is 0-indexed.
func (vs *VaultKeySatSolver) RecordFalseKey(keyIndex int) {
	clause := make([]int, 1)
	clause[0] = -vs.keyVars[keyIndex]
	vs.failureClauses = append(vs.failureClauses, clause)
}

// GetStats returns statistics about the solver's search process.
func (vs *VaultKeySatSolver) GetStats() (attempts, constraints int) {
	return vs.attemptCount, len(vs.failureClauses)
}

// GetTestedSets returns the history of all tested key index sets (for debugging/reporting).
func (vs *VaultKeySatSolver) GetTestedSets() [][]int {
	return vs.testedSets
}
