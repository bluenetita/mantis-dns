from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class BlockMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BLOCK_MODE_UNSPECIFIED: _ClassVar[BlockMode]
    BLOCK_MODE_NXDOMAIN: _ClassVar[BlockMode]
    BLOCK_MODE_ZERO_IP: _ClassVar[BlockMode]
    BLOCK_MODE_REDIRECT: _ClassVar[BlockMode]

class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ACTION_UNSPECIFIED: _ClassVar[Action]
    ACTION_BLOCK: _ClassVar[Action]
    ACTION_LOG_ONLY: _ClassVar[Action]
    ACTION_ALLOW: _ClassVar[Action]

class FailurePolicy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FAILURE_POLICY_UNSPECIFIED: _ClassVar[FailurePolicy]
    FAIL_OPEN: _ClassVar[FailurePolicy]
    FAIL_CLOSED: _ClassVar[FailurePolicy]
BLOCK_MODE_UNSPECIFIED: BlockMode
BLOCK_MODE_NXDOMAIN: BlockMode
BLOCK_MODE_ZERO_IP: BlockMode
BLOCK_MODE_REDIRECT: BlockMode
ACTION_UNSPECIFIED: Action
ACTION_BLOCK: Action
ACTION_LOG_ONLY: Action
ACTION_ALLOW: Action
FAILURE_POLICY_UNSPECIFIED: FailurePolicy
FAIL_OPEN: FailurePolicy
FAIL_CLOSED: FailurePolicy

class Bundle(_message.Message):
    __slots__ = ("tenant_id", "group_id", "version", "built_at_unix", "categories", "allow_overrides", "deny_overrides", "on_load_failure", "block_response", "signature", "signer_key_id")
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    BUILT_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    ALLOW_OVERRIDES_FIELD_NUMBER: _ClassVar[int]
    DENY_OVERRIDES_FIELD_NUMBER: _ClassVar[int]
    ON_LOAD_FAILURE_FIELD_NUMBER: _ClassVar[int]
    BLOCK_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNER_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    tenant_id: str
    group_id: str
    version: int
    built_at_unix: int
    categories: _containers.RepeatedCompositeFieldContainer[CategorySet]
    allow_overrides: _containers.RepeatedScalarFieldContainer[str]
    deny_overrides: _containers.RepeatedScalarFieldContainer[str]
    on_load_failure: FailurePolicy
    block_response: BlockResponse
    signature: bytes
    signer_key_id: str
    def __init__(self, tenant_id: _Optional[str] = ..., group_id: _Optional[str] = ..., version: _Optional[int] = ..., built_at_unix: _Optional[int] = ..., categories: _Optional[_Iterable[_Union[CategorySet, _Mapping]]] = ..., allow_overrides: _Optional[_Iterable[str]] = ..., deny_overrides: _Optional[_Iterable[str]] = ..., on_load_failure: _Optional[_Union[FailurePolicy, str]] = ..., block_response: _Optional[_Union[BlockResponse, _Mapping]] = ..., signature: _Optional[bytes] = ..., signer_key_id: _Optional[str] = ...) -> None: ...

class BlockResponse(_message.Message):
    __slots__ = ("mode", "redirect_ipv4", "redirect_ipv6", "ttl_seconds")
    MODE_FIELD_NUMBER: _ClassVar[int]
    REDIRECT_IPV4_FIELD_NUMBER: _ClassVar[int]
    REDIRECT_IPV6_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    mode: BlockMode
    redirect_ipv4: str
    redirect_ipv6: str
    ttl_seconds: int
    def __init__(self, mode: _Optional[_Union[BlockMode, str]] = ..., redirect_ipv4: _Optional[str] = ..., redirect_ipv6: _Optional[str] = ..., ttl_seconds: _Optional[int] = ...) -> None: ...

class CategorySet(_message.Message):
    __slots__ = ("category_id", "source_feed_id", "feed_version", "license", "bloom", "bloom_bits", "action")
    CATEGORY_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FEED_ID_FIELD_NUMBER: _ClassVar[int]
    FEED_VERSION_FIELD_NUMBER: _ClassVar[int]
    LICENSE_FIELD_NUMBER: _ClassVar[int]
    BLOOM_FIELD_NUMBER: _ClassVar[int]
    BLOOM_BITS_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    category_id: str
    source_feed_id: str
    feed_version: str
    license: str
    bloom: BloomParams
    bloom_bits: bytes
    action: Action
    def __init__(self, category_id: _Optional[str] = ..., source_feed_id: _Optional[str] = ..., feed_version: _Optional[str] = ..., license: _Optional[str] = ..., bloom: _Optional[_Union[BloomParams, _Mapping]] = ..., bloom_bits: _Optional[bytes] = ..., action: _Optional[_Union[Action, str]] = ...) -> None: ...

class BloomParams(_message.Message):
    __slots__ = ("num_hashes", "num_bits", "seed")
    NUM_HASHES_FIELD_NUMBER: _ClassVar[int]
    NUM_BITS_FIELD_NUMBER: _ClassVar[int]
    SEED_FIELD_NUMBER: _ClassVar[int]
    num_hashes: int
    num_bits: int
    seed: int
    def __init__(self, num_hashes: _Optional[int] = ..., num_bits: _Optional[int] = ..., seed: _Optional[int] = ...) -> None: ...
