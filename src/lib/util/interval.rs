// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2023 Alexander Seifarth
//
// This file is part of `someip-rsmw`.
// `someip-rsmw` is free software: you can redistribute it and/or modify it under the terms
// of the GNU General Public License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
// `someip-rsmw` is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Foobar.
// If not, see <https://www.gnu.org/licenses/>.

use std::clone::Clone;
use std::cmp::max;

pub fn merge_new(intervals: &Vec<(usize, usize)>, new_intv: (usize, usize)) -> Vec<(usize, usize)> {
    let mut intvs = intervals.clone();
    intvs.push(new_intv);
    intvs.sort();
    return merge_intervals(&intvs)
}

/// Merges the intervals into non-intersecting intervals.
/// The intervals (a,b) must fulfill a<=b and the `intervals` vector must be lexicographically
/// ordered.
pub fn merge_intervals(intervals: &Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if intervals.is_empty() {
        return intervals.clone()
    }

    let mut news = Vec::new();
    let mut it = intervals.iter();
    let mut a = it.next().unwrap().clone();
    loop {
        let b = it.next();
        if let Some(bv) = b {
            if (a.1 + 1) >= bv.0 {
                a = (a.0, max(a.1, bv.1.clone()))
            }
            else {
                news.push(a);
                a = bv.clone();
                continue;
            }
        }
        else {
            news.push(a);
            break;
        }
    }
    return news
}

#[cfg(test)]
mod tests {
    use crate::util::interval::merge_intervals;

    #[test]
    fn test_merge() {
        let intvs = vec![(1,3), (4,8), (8,9), (8, 11), (10, 13)];
        let mgd = merge_intervals(&intvs);
        assert_eq!(mgd, vec![(1,13)]);
    }

    #[test]
    fn test_merge2() {
        let intvs = vec![(1,3), (4,8), (10, 11), (10, 13)];
        let mgd = merge_intervals(&intvs);
        assert_eq!(mgd, vec![(1,8), (10,13)]);
    }

}