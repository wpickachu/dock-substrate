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
type CredentialId = [u8; 32]; // XXX: Call this something more general. It will be useful to revoke
                              // things that are not credentials.

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
pub struct Revoke<BlockNumber> {
    /// The registry on which to operate
    registry_id: RegistryId,
    /// Credential ids which will be revoked
    credential_ids: BTreeSet<CredentialId>,
    /// For replay protection.
    last_modified: BlockNumber,
}

decl_storage! {
    trait Store for Module<T: Trait> as TemplateModule {
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
            registry_id: RegistryId,
            credential_ids: BTreeSet<CredentialId>,
            sigs: BTreeMap<Did, did::Signature>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // setup
            let (registry, last_modified) =
                Registries::<T>::get(&registry_id).ok_or("registry does not exists")?;
            let signers: Vec<_> = sigs.keys().collect();
            let payload = super::StateChange::Revoke(Revoke {
                registry_id,
                credential_ids: credential_ids.clone(),
                last_modified,
            })
            .encode();
            let current_block = system::Module::<T>::block_number();

            // check
            ensure!(
                registry.policy.satisfied_by(&signers),
                "policy requirements not met"
            );
            for (signer, sig) in sigs {
                ensure!(
                    did::Module::<T>::verify_sig_from_Did(&sig, &payload, &signer)?,
                    "invalid signature"
                );
            }
            for cred_id in &credential_ids {
                ensure!(
                    Revocations::<T>::get(&(registry_id, *cred_id)).is_none(),
                    "credential already revoked"
                );
            }

            // execute
            for cred_id in &credential_ids {
                Revocations::<T>::insert(&(registry_id, *cred_id), current_block);
            }
            Registries::<T>::insert(&registry_id, (registry, current_block));

            Ok(())
        }
    }
}
