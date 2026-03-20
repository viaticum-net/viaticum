#[cfg(test)]
mod tests {
    use crate::cluster::{
        derive_device_key, derive_epoch_key, derive_master_key, epoch_for_time,
        esi_namespace_end, esi_namespace_start, issue_device_certificate, issue_revocation,
        master_identity, next_epoch, verify_device_certificate, verify_revocation, ClusterError,
        EpochCounter,
    };
    use crate::types::{DeviceId, Timestamp};

    #[test]
    fn derive_master_key_is_deterministic() {
        let seed = [0u8; 32];
        let key1 = derive_master_key(&seed).unwrap();
        let key2 = derive_master_key(&seed).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn derive_device_key_differs_from_master() {
        let seed = [1u8; 32];
        let master = derive_master_key(&seed).unwrap();
        let device_id = DeviceId([2u8; 16]);
        let device = derive_device_key(&seed, &device_id).unwrap();
        assert_ne!(master.to_bytes(), device.to_bytes());
    }

    #[test]
    fn derive_device_key_differs_per_device() {
        let seed = [3u8; 32];
        let device_id_a = DeviceId([0u8; 16]);
        let device_id_b = DeviceId([1u8; 16]);
        let key_a = derive_device_key(&seed, &device_id_a).unwrap();
        let key_b = derive_device_key(&seed, &device_id_b).unwrap();
        assert_ne!(key_a.to_bytes(), key_b.to_bytes());
    }

    #[test]
    fn derive_epoch_key_differs_per_epoch() {
        let seed = [4u8; 32];
        let epoch_0 = derive_epoch_key(&seed, EpochCounter(0)).unwrap();
        let epoch_1 = derive_epoch_key(&seed, EpochCounter(1)).unwrap();
        assert_ne!(epoch_0.key_bytes, epoch_1.key_bytes);
    }

    #[test]
    fn master_identity_round_trip() {
        let seed = [5u8; 32];
        let master_key = derive_master_key(&seed).unwrap();
        let identity = master_identity(&master_key);
        assert_eq!(identity.0, master_key.verifying_key().to_bytes());
    }

    #[test]
    fn issue_and_verify_device_certificate() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([3u8; 16]);
        let device_pub = [4u8; 32];
        let cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1000));
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
    }

    #[test]
    fn verify_certificate_with_wrong_master_fails() {
        let master_a = derive_master_key(&[1u8; 32]).unwrap();
        let master_b = derive_master_key(&[2u8; 32]).unwrap();
        let device_id = DeviceId([3u8; 16]);
        let device_pub = [4u8; 32];
        let cert = issue_device_certificate(&master_a, device_id, device_pub, Timestamp(1000));
        let result = verify_device_certificate(&cert, &master_identity(&master_b));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn verify_certificate_tampered_signature_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([3u8; 16]);
        let device_pub = [4u8; 32];
        let mut cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1000));
        cert.signature[0] ^= 1;
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn verify_certificate_tampered_device_id_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([3u8; 16]);
        let device_pub = [4u8; 32];
        let mut cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1000));
        cert.device_id = DeviceId([0xFF; 16]);
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn issue_and_verify_revocation() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([5u8; 16]);
        let cert = issue_revocation(&master_key, device_id, Timestamp(5000), EpochCounter(1));
        let result = verify_revocation(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
    }

    #[test]
    fn tampered_revocation_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([5u8; 16]);
        let mut cert = issue_revocation(&master_key, device_id, Timestamp(5000), EpochCounter(1));
        cert.new_epoch.0 += 1;
        let result = verify_revocation(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn epoch_for_time_basic() {
        let history = vec![
            (EpochCounter(0), Timestamp(0)),
            (EpochCounter(1), Timestamp(1000)),
            (EpochCounter(2), Timestamp(2000)),
        ];
        assert_eq!(epoch_for_time(&history, Timestamp(0)), EpochCounter(0));
        assert_eq!(epoch_for_time(&history, Timestamp(500)), EpochCounter(0));
        assert_eq!(epoch_for_time(&history, Timestamp(1000)), EpochCounter(1));
        assert_eq!(epoch_for_time(&history, Timestamp(1500)), EpochCounter(1));
        assert_eq!(epoch_for_time(&history, Timestamp(2000)), EpochCounter(2));
        assert_eq!(epoch_for_time(&history, Timestamp(9999)), EpochCounter(2));
    }

    #[test]
    fn epoch_for_time_before_genesis() {
        let history = vec![(EpochCounter(0), Timestamp(100))];
        assert_eq!(epoch_for_time(&history, Timestamp(50)), EpochCounter(0));
    }

    #[test]
    fn esi_namespace_no_overlap() {
        assert_eq!(esi_namespace_start(0), 0);
        assert_eq!(esi_namespace_start(1), 1_048_576);
        assert_eq!(esi_namespace_end(0), esi_namespace_start(1));

        for i in 0u8..15 {
            assert_eq!(esi_namespace_end(i), esi_namespace_start(i + 1));
        }
        assert_eq!(esi_namespace_start(15), 15 * (1 << 20));
        assert_eq!(esi_namespace_end(15), 16 * (1 << 20));
    }

    #[test]
    fn full_cluster_flow() {
        let seed = [42u8; 32];
        let master_key = derive_master_key(&seed).unwrap();
        let identity = master_identity(&master_key);

        let device_a = DeviceId([10u8; 16]);
        let device_b = DeviceId([20u8; 16]);
        let pub_a = [11u8; 32];
        let pub_b = [21u8; 32];

        let cert_a = issue_device_certificate(&master_key, device_a, pub_a, Timestamp(100));
        let cert_b = issue_device_certificate(&master_key, device_b, pub_b, Timestamp(200));

        assert!(verify_device_certificate(&cert_a, &identity).is_ok());
        assert!(verify_device_certificate(&cert_b, &identity).is_ok());

        let revocation = issue_revocation(&master_key, device_a, Timestamp(1000), EpochCounter(1));
        assert!(verify_revocation(&revocation, &identity).is_ok());
        assert_eq!(revocation.new_epoch, EpochCounter(1));
        assert_eq!(next_epoch(EpochCounter(0)), EpochCounter(1));

        let epoch_key_0 = derive_epoch_key(&seed, EpochCounter(0)).unwrap();
        let epoch_key_1 = derive_epoch_key(&seed, EpochCounter(1)).unwrap();
        assert_ne!(epoch_key_0.key_bytes, epoch_key_1.key_bytes);

        let history = vec![
            (EpochCounter(0), Timestamp(0)),
            (EpochCounter(1), Timestamp(1000)),
        ];
        assert_eq!(epoch_for_time(&history, Timestamp(500)), EpochCounter(0));
        assert_eq!(epoch_for_time(&history, Timestamp(1500)), EpochCounter(1));
    }
}
