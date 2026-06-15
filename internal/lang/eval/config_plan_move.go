// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package eval

import (
	"context"
	"fmt"
	"iter"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/refactoring"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// FindAddressesMovedFromHere returns all of the addresses that this address will be moved to,
// that is, it follows the move statements' in their logical way.
//
// Importantly, this function assumes the underlying move statement graph
// has no cycles. Be sure to check for that before calling this method, or
// it may take a while to return.
//
// A flag is returned and set to true if the move was ambiguous.
func (o *PlanningOracle) FindAddressesMovedFromHere(ctx context.Context, addr addrs.AbsResourceInstance) ([]addrs.AbsResourceInstance, tfdiags.Diagnostics) {
	return o.findAddressesByMove(ctx, addr, false)
}

// FindAddressesMovedToHere returns all of the addresses that might be moved to this address,
// that is, has a series of move statements with From addresses that eventually lead to
// addr as a To address.
//
// Importantly, this function assumes the underlying move statement graph
// has no cycles. Be sure to check for that before calling this method, or
// it may take a while to return.
//
// A flag is returned and set to true if the move was ambiguous.
//
// TODO does this even work??
func (o *PlanningOracle) FindAddressesMovedToHere(ctx context.Context, addr addrs.AbsResourceInstance) ([]addrs.AbsResourceInstance, tfdiags.Diagnostics) {
	return o.findAddressesByMove(ctx, addr, true)
}

type moveInfo struct {
	addr addrs.AbsResourceInstance
	stmt refactoring.MoveStatement
}

func mapToSlice(m map[addrs.UniqueKey]*moveInfo) iter.Seq[addrs.AbsResourceInstance] {
	return func(yield func(addrs.AbsResourceInstance) bool) {
		for _, mi := range m {
			if !yield(mi.addr) {
				return
			}
		}
	}
}

func (o *PlanningOracle) findAddressesByMove(ctx context.Context, addr addrs.AbsResourceInstance, reverse bool) ([]addrs.AbsResourceInstance, tfdiags.Diagnostics) {
	var diags tfdiags.Diagnostics
	output := make([]addrs.AbsResourceInstance, 1)
	output[0] = addr
	prevAddr := addr

	// We're never going to "move" more times
	// than there are move statements
	for range len(o.moveStatements) {
		addresses := make(map[addrs.UniqueKey]*moveInfo)
		for _, move := range o.moveStatements {
			from, to := move.From, move.To
			if reverse {
				from, to = move.To, move.From
			}
			if movedAddr, moved := prevAddr.MoveDestination(from, to); moved {
				// Note: using the movedAddr.UniqueKey() is equivalent to checking addrs.Equivalent
				// So all addresses in this map will be uniquely determined
				if _, ok := addresses[movedAddr.UniqueKey()]; !ok {
					addresses[movedAddr.UniqueKey()] = &moveInfo{addr: movedAddr, stmt: move}
				}
			}
		}
		if len(addresses) == 0 {
			break
		}
		if len(addresses) > 1 {
			// more than one address means an ambiguous move
			var first *moveInfo
			for _, mi := range addresses {
				if first == nil {
					// TODO: might have to set "first" above, since the map may not be ordered the way we "expect"
					first = mi
					continue
				}
				ambiguityDiag := oneFromManyTo(first, mi)
				if reverse {
					ambiguityDiag = manyFromOneTo(first, mi)
				}
				diags = diags.Append(ambiguityDiag)

			}
			return slices.Collect(mapToSlice(addresses)), diags
		}
		// There is exactly one address in addresses.
		// TODO is there a more... idk, elegant way to extract it?
		prevAddr = slices.Collect(mapToSlice(addresses))[0]
		output = append(output, prevAddr)
	}
	return output, diags
}

// oneFromManyTo formats an existing piece of movement info and a conflicting ambiguous movement statement
// into a diagnostic error
func oneFromManyTo(first *moveInfo, mi *moveInfo) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "Ambiguous move statements",
		Detail: fmt.Sprintf(
			"A statement at %s declared that %s moved to %s, but this statement instead declares that it moved to %s.\n\nEach %s can move to only one destination %s.",
			first.stmt.DeclRange.StartString(), mi.stmt.From, first.stmt.To, mi.stmt.To,
			mi.addr.Noun(), mi.addr.ShortNoun(),
		),
		Subject: mi.stmt.DeclRange.ToHCL().Ptr(),
	}
}

// manyFromOneTo formats an existing piece of movement info and a conflicting ambiguous movement statement
// into a diagnostic error
// TODO: maybe we can unify the manyFromOneTo with oneFromManyTo?
func manyFromOneTo(first *moveInfo, mi *moveInfo) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "Ambiguous move statements",
		Detail: fmt.Sprintf(
			"A statement at %s declared that %s moved to %s, but this statement instead declares that %s moved there.\n\nEach %s can have moved from only one source %s.",
			first.stmt.DeclRange.StartString(), first.stmt.From, mi.stmt.To, mi.stmt.From,
			mi.addr.Noun(), mi.addr.ShortNoun(),
		),
		Subject: mi.stmt.DeclRange.ToHCL().Ptr(),
	}
}
