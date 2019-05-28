/*
 *  This software is a computer program whose purpose is to compute validitiy of
 *  identification data.
 *
 *  Copyright (C) 2017 Th!nk Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, only version 2.0.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/* Original LibreAuth License */

/*
 * Copyright Rodolphe Breard (2017)
 * Author: Rodolphe Breard (2017)
 *
 * This software is a computer program whose purpose is to [describe
 * functionalities and technical features of your software].
 *
 * This software is governed by the CeCILL  license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL license and that you accept its terms.
 */

use hex;

pub fn from_hex(s: &String) -> Result<Vec<u8>, ()> {
    hex::decode(s).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::from_hex;

    #[test]
    fn test_valid_data() {
        let examples: [(&str, Vec<u8>); 4] = [
            (
                "576f6c6f6c6f203432202121203e2e3c",
                vec![
                    87, 111, 108, 111, 108, 111, 32, 52, 50, 32, 33, 33, 32, 62, 46, 60,
                ],
            ),
            ("420069", vec![66, 0, 105]),
            ("0000000000", vec![0, 0, 0, 0, 0]),
            ("Ecc25519", vec![236, 194, 85, 25]),
        ];

        for &(ref hex_str, ref expected_data) in examples.iter() {
            assert_eq!(&from_hex(&hex_str.to_string()).unwrap(), expected_data);
        }
    }

    #[test]
    fn test_invalid_data() {
        match from_hex(&"123z12".to_string()) {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_invalid_size() {
        match from_hex(&"123".to_string()) {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_no_data() {
        match from_hex(&"".to_string()) {
            Ok(v) => assert_eq!(v, vec![]),
            Err(_) => assert!(false),
        }
    }
}
