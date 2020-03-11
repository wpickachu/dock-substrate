use crate::did::{self, Did};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use codec::{Decode, Encode};
use frame_support::{decl_module, decl_storage, dispatch::DispatchResult, ensure};
use system::ensure_signed;

pub trait Trait: system::Trait + did::Trait {}

type RegistryId = [u8; 32];
type CredentialId = [u8; 32];

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub enum Policy {
    OneOf {
        /// Set of dids allowed to modify a registry.
        controllers: BTreeSet<Did>,
    },
}

impl Policy {
    /// Check for user error in the construction of self.
    /// if self is invalid, return `Err(reason)`, else return `Ok(())`.
    fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::OneOf { controllers } if controllers.len() != 0 => Ok(()),
            Self::OneOf { .. } => Err("that policy requires at least one controller"),
        }
    }

    /// Return whether a signature by each member of verifier_set would satisfy the conditions of
    /// this policy.
    fn satisfied_by(&self, verifier_set: &[&Did]) -> bool {
        match self {
            Self::OneOf { controllers } => {
                verifier_set.len() == 1
                    && verifier_set
                        .iter()
                        .all(|verifier| controllers.contains(*verifier))
            }
        }
    }
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct Registry {
    /// Who is allowed to update this registry.
    policy: Policy,
    /// true: credentials can be revoked, but not un-revoked
    /// false: credentials can be revoked and un-revoked
    add_only: bool,
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct Revoke {
    /// The registry on which to operate
    rev_reg_id: RegistryId,
    /// Credential ids which will be revoked
    cred_ids: BTreeSet<CredentialId>,
}

decl_storage! {
    trait Store for Module<T: Trait> as TemplateModule {
        // It's insane for Registry to impl Default.
        Registries: map RegistryId => Option<(Registry, T::BlockNumber)>;

        Revocations: map (RegistryId, CredentialId)
            => Option<T::BlockNumber>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        pub fn new_registry(origin, id: RegistryId, registry: Registry) -> DispatchResult {
            ensure_signed(origin)?;
            registry.policy.validate()?;
            ensure!(Registries::<T>::get(&id).is_none(), "registry already exists with that id");
            Registries::<T>::insert(&id, (registry, system::Module::<T>::block_number()));
            Ok(())
        }

        pub fn revoke(
            origin,
            to_revoke: (Revoke, super::BlockNumber),
            sigs: BTreeMap<Did, did::Signature>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let (registry, blkn) =
                Registries::<T>::get(&to_revoke.0.rev_reg_id).ok_or("registry does not exists")?;
            let signers: Vec<_> = sigs.keys().collect();
            ensure!(
                registry.policy.satisfied_by(&signers),
                "signer set does not meet policy requirements"
            );
            let (command, last_updated) = to_revoke;
            let payload = super::StateChange::Revoke {
                command,
                last_updated,
            }
            .encode();
            for (signer, sig) in sigs {
                ensure!(
                    did::Module::<T>::verify_sig_from_Did(&sig, &payload, &signer)?,
                    "invalid signature"
                );
            }
            todo!("replay protection")
        }
    }
}
