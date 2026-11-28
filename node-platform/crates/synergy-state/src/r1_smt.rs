//! Exact QACE SMT384 /02 reference construction and canonical point proofs.
use crate::r1::{hash_encoded, R1StateError, R1StateMap};
use synergy_protocol_types::c14n02::Encoder;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1PointProof {
    pub bitmap: [u8; 48],
    pub siblings: Vec<[u8; 48]>,
}
struct Leaf {
    path: [u8; 48],
    key: Vec<u8>,
    digest: [u8; 48],
}
fn bit(path: &[u8; 48], depth: usize) -> bool {
    path[depth / 8] & (0x80 >> (depth % 8)) != 0
}
fn node(depth: usize, left: &[u8; 48], right: &[u8; 48]) -> Result<[u8; 48], R1StateError> {
    let mut e = Encoder::new(98);
    e.u16(depth as u16)?;
    e.fixed(left)?;
    e.fixed(right)?;
    hash_encoded("QACE/STATE/NODE/02", &[&e.finish()?])
}
fn empties() -> Result<[[u8; 48]; 385], R1StateError> {
    let mut a = [[0u8; 48]; 385];
    a[384] = hash_encoded("QACE/STATE/EMPTY/02", &[])?;
    for d in (0..384).rev() {
        a[d] = node(d, &a[d + 1], &a[d + 1])?;
    }
    Ok(a)
}
fn leaves(map: &R1StateMap) -> Result<Vec<Leaf>, R1StateError> {
    leaves_with(map, |key| hash_encoded("QACE/STATE/PATH/02", &[key]))
}
fn leaves_with(
    map: &R1StateMap,
    path_hash: impl Fn(&[u8]) -> Result<[u8; 48], R1StateError>,
) -> Result<Vec<Leaf>, R1StateError> {
    leaves_checked(map, path_hash, &mut |_| Ok(()))
}
fn leaves_checked(
    map: &R1StateMap,
    path_hash: impl Fn(&[u8]) -> Result<[u8; 48], R1StateError>,
    check: &mut impl FnMut(u64) -> Result<(), R1StateError>,
) -> Result<Vec<Leaf>, R1StateError> {
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map.entries() {
        check(2)?;
        let key = k.canonical_bytes()?;
        let value = v.canonical_bytes()?;
        let path = path_hash(&key)?;
        let digest = hash_encoded("QACE/STATE/LEAF/02", &[&key, &value])?;
        out.push(Leaf { path, key, digest });
    }
    out.sort_by_key(|x| x.path);
    check(0)?;
    if out.windows(2).any(|x| x[0].path == x[1].path) {
        return Err(R1StateError::PathCollision);
    }
    Ok(out)
}
fn subtree(rows: &[Leaf], depth: usize, empty: &[[u8; 48]; 385]) -> Result<[u8; 48], R1StateError> {
    subtree_checked(rows, depth, empty, &mut |_| Ok(()))
}
fn subtree_checked(
    rows: &[Leaf],
    depth: usize,
    empty: &[[u8; 48]; 385],
    check: &mut impl FnMut(u64) -> Result<(), R1StateError>,
) -> Result<[u8; 48], R1StateError> {
    if rows.is_empty() {
        return Ok(empty[depth]);
    }
    if depth == 384 {
        return if rows.len() == 1 {
            Ok(rows[0].digest)
        } else {
            Err(R1StateError::PathCollision)
        };
    }
    let split = rows.partition_point(|x| !bit(&x.path, depth));
    check(1)?;
    node(
        depth,
        &subtree_checked(&rows[..split], depth + 1, empty, check)?,
        &subtree_checked(&rows[split..], depth + 1, empty, check)?,
    )
}
pub fn root(map: &R1StateMap) -> Result<[u8; 48], R1StateError> {
    subtree(&leaves(map)?, 0, &empties()?)
}
/// Local work limits do not change the authenticated root. Exhaustion is a
/// resource/unavailability result, never a claim that the state is invalid.
pub fn root_with_limits(
    map: &R1StateMap,
    deadline: std::time::Instant,
    remaining_hashes: &mut u64,
) -> Result<[u8; 48], R1StateError> {
    let mut check = |n: u64| {
        if std::time::Instant::now() >= deadline {
            return Err(R1StateError::ResourceLimit);
        }
        *remaining_hashes = remaining_hashes
            .checked_sub(n)
            .ok_or(R1StateError::ResourceLimit)?;
        Ok(())
    };
    check(385)?;
    let empty = empties()?;
    let rows = leaves_checked(
        map,
        |k| hash_encoded("QACE/STATE/PATH/02", &[k]),
        &mut check,
    )?;
    subtree_checked(&rows, 0, &empty, &mut check)
}
pub fn prove(map: &R1StateMap, key: &crate::r1::R1StateKey) -> Result<R1PointProof, R1StateError> {
    let encoded_key = key.canonical_bytes()?;
    let path = hash_encoded("QACE/STATE/PATH/02", &[&encoded_key])?;
    let all = leaves(map)?;
    let empty = empties()?;
    let mut rows = all.as_slice();
    let mut proof = R1PointProof {
        bitmap: [0; 48],
        siblings: Vec::new(),
    };
    for d in 0..384 {
        let split = rows.partition_point(|x| !bit(&x.path, d));
        let (own, other) = if bit(&path, d) {
            (&rows[split..], &rows[..split])
        } else {
            (&rows[..split], &rows[split..])
        };
        let sibling = subtree(other, d + 1, &empty)?;
        if sibling != empty[d + 1] {
            proof.bitmap[d / 8] |= 0x80 >> (d % 8);
            proof.siblings.push(sibling);
        }
        rows = own;
    }
    if rows
        .first()
        .is_some_and(|x| x.path == path && x.key != encoded_key)
    {
        return Err(R1StateError::PathCollision);
    }
    Ok(proof)
}
pub fn verify(
    root: &[u8; 48],
    key: &crate::r1::R1StateKey,
    value: Option<&crate::r1::R1StateValue>,
    proof: &R1PointProof,
) -> Result<(), R1StateError> {
    if proof.siblings.len() > 384
        || proof
            .bitmap
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum::<usize>()
            != proof.siblings.len()
    {
        return Err(R1StateError::Proof);
    }
    let encoded_key = key.canonical_bytes()?;
    let path = hash_encoded("QACE/STATE/PATH/02", &[&encoded_key])?;
    let empty = empties()?;
    let mut by_depth = [[0u8; 48]; 384];
    let mut cursor = 0;
    for d in 0..384 {
        by_depth[d] = if bit(&proof.bitmap, d) {
            let sibling = proof.siblings[cursor];
            cursor += 1;
            if sibling == empty[d + 1] {
                return Err(R1StateError::Proof);
            }
            sibling
        } else {
            empty[d + 1]
        };
    }
    let mut current = match value {
        Some(v) => hash_encoded("QACE/STATE/LEAF/02", &[&encoded_key, &v.canonical_bytes()?])?,
        None => empty[384],
    };
    for d in (0..384).rev() {
        current = if bit(&path, d) {
            node(d, &by_depth[d], &current)?
        } else {
            node(d, &current, &by_depth[d])?
        };
    }
    if &current != root {
        return Err(R1StateError::Proof);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1::*;
    use synergy_address::r1_public::NativeIdentityPresentation;
    fn key(n: u8) -> R1StateKey {
        R1StateKey::native(
            R1StateDomain::NativeBalance,
            &NativeIdentityPresentation::from_raw("syns", [n; 48])
                .unwrap()
                .to_text(),
        )
        .unwrap()
    }
    #[test]
    fn membership_absence_update_delete_and_order_are_exact() {
        let mut a = R1StateMap::new();
        let v = R1StateValue::NativeBalance {
            amount_nwei: u128::MAX,
        };
        a.insert(key(1), v.clone()).unwrap();
        a.insert(key(2), R1StateValue::NativeBalance { amount_nwei: 0 })
            .unwrap();
        let root = a.root().unwrap();
        verify(&root, &key(1), Some(&v), &prove(&a, &key(1)).unwrap()).unwrap();
        verify(&root, &key(3), None, &prove(&a, &key(3)).unwrap()).unwrap();
        assert!(verify(&root, &key(1), None, &prove(&a, &key(1)).unwrap()).is_err());
        let mut b = R1StateMap::new();
        b.insert(key(2), R1StateValue::NativeBalance { amount_nwei: 0 })
            .unwrap();
        b.insert(key(1), v).unwrap();
        assert_eq!(root, b.root().unwrap());
        b.remove(&key(1));
        b.remove(&key(2));
        assert_eq!(b.root().unwrap(), R1StateMap::new().root().unwrap());
    }
    #[test]
    fn malformed_and_redundant_proofs_reject() {
        let map = R1StateMap::new();
        let root = map.root().unwrap();
        let mut proof = prove(&map, &key(4)).unwrap();
        proof.bitmap[0] = 0x80;
        proof.siblings.push(empties().unwrap()[1]);
        assert!(verify(&root, &key(4), None, &proof).is_err());
        proof.siblings.clear();
        assert!(verify(&root, &key(4), None, &proof).is_err());
    }
    #[test]
    fn injected_path_collision_never_overwrites_a_distinct_key() {
        let mut map = R1StateMap::new();
        map.insert(key(1), R1StateValue::NativeBalance { amount_nwei: 1 })
            .unwrap();
        map.insert(key(2), R1StateValue::NativeBalance { amount_nwei: 2 })
            .unwrap();
        assert!(matches!(
            leaves_with(&map, |_| Ok([0x55; 48])),
            Err(R1StateError::PathCollision)
        ));
        assert_eq!(map.len(), 2);
    }
    #[test]
    fn independent_python_c14n02_vectors_match_full_roots() {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/qace_smt384_public.json"))
                .unwrap();
        for case in data["cases"].as_array().unwrap() {
            let mut map = R1StateMap::new();
            for row in case["entries"].as_array().unwrap() {
                map.insert(
                    key(row["public_raw_byte"].as_u64().unwrap() as u8),
                    R1StateValue::NativeBalance {
                        amount_nwei: row["amount_nwei"].as_str().unwrap().parse().unwrap(),
                    },
                )
                .unwrap();
            }
            let actual = map
                .root()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(actual, case["root_hex"].as_str().unwrap());
        }
    }
}
