use super::DID;
use alloc::{collections::BTreeSet, string::String};
use codec::{Decode, Encode};
use core::marker::PhantomData;
use frame_support::{decl_module, decl_storage, dispatch::DispatchResult, ensure};
use system::ensure_signed;

pub trait Trait: system::Trait {}

type RegistryId = String;
type CredentialId = String;

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug, PartialOrd, Ord)]
pub struct Blake2sHash<T> {
    pub hash: [u8; 32],
    _spook: PhantomData<T>,
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub enum Policy {
    OneOf {
        /// Set of dids allowed to modify a registry.
        controllers: BTreeSet<Blake2sHash<DID>>,
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
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct Registry {
    /// Who is allowed to update this registry.
    policy: Policy,
    /// true: credentials can be revoked, but not un-revoked
    /// false: credentials can be revoked and un-revoked
    add_only: bool,
}

decl_storage! {
    trait Store for Module<T: Trait> as TemplateModule {
        // It's insane for Registry to impl Default.
        Registries: map Blake2sHash<RegistryId> => Option<(Registry, T::BlockNumber)>;

        Revocations: map (Blake2sHash<RegistryId>, Blake2sHash<CredentialId>)
            => Option<T::BlockNumber>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        pub fn new_registry(origin, id: Blake2sHash<RegistryId>, registry: Registry) -> DispatchResult {
            ensure_signed(origin)?;
            registry.policy.validate()?;
            ensure!(Registries::<T>::get(&id).is_none(), "registry already exists with that id");
            Registries::<T>::insert(&id, (registry, system::Module::<T>::block_number()));
            Ok(())
        }

        pub fn revoke(origin) -> DispatchResult {
            ensure_signed(origin)?;
            todo!()
        }
    }
}
