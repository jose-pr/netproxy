"""Client credentials for mTLS: a keystore query or an identity, built into an
``ssl.SSLContext`` on first use."""

from __future__ import annotations

import ssl
import threading
from typing import Any, Callable, Mapping, Optional, Tuple, Union

import sslcontext
from sslcontext.backends import get as get_backend

from .exceptions import CredentialUnavailableError

__all__ = ["Credential"]

IdentitySource = Union["sslcontext.Identity", Callable[[], "sslcontext.Identity"]]


class Credential:
    """A client identity for mTLS, turned into a client ``SSLContext`` lazily.

    Give one source: ``identity`` (an :class:`sslcontext.Identity`, or a
    callable returning one); ``pem``, a ``(certificate, key, password)``
    tuple for :func:`sslcontext.load_pem` (see :meth:`from_pem`); or a
    keystore ``backend`` name with its constructor
    ``options`` (``store``, ``module``, ``pin``, ...) and a ``query`` for
    :meth:`sslcontext.backends.Backend.find_identity` (``subject``,
    ``thumbprint``, ``label``, ...). ``verify``, ``cafile``, ``capath``,
    ``cadata`` and ``minimum_version`` shape how the destination's
    certificate is checked, as in :func:`sslcontext.create_context`.

    Building touches the keystore, so it may block: the server calls
    :meth:`context` from a worker thread. The context is cached until
    :meth:`invalidate`; a failure is not cached, so the next connection tries
    again.
    """

    def __init__(
        self,
        identity: Optional[IdentitySource] = None,
        *,
        backend: Optional[str] = None,
        pem: Optional[Tuple[Any, Any, Any]] = None,
        options: Optional[Mapping[str, Any]] = None,
        query: Optional[Mapping[str, Any]] = None,
        verify: Union[bool, str, None] = None,
        cafile: Optional[str] = None,
        capath: Optional[str] = None,
        cadata: Union[str, bytes, None] = None,
        minimum_version: Optional[ssl.TLSVersion] = None,
        name: str = "",
    ) -> None:
        if sum(source is not None for source in (identity, backend, pem)) != 1:
            raise ValueError("give exactly one of identity=, backend= or pem=")
        self._pem = pem
        if backend is not None:
            get_backend(backend)  # an unknown name is a caller's error, now
        self._identity = identity
        self.backend = backend
        self.options = dict(options or {})
        self.query = dict(query or {})
        self._context_options = {
            "verify": verify,
            "cafile": cafile,
            "capath": capath,
            "cadata": cadata,
            "minimum_version": minimum_version,
        }
        self.name = name
        self._lock = threading.Lock()
        self._context: Optional[ssl.SSLContext] = None

    def __repr__(self) -> str:
        if self.backend:
            source = f"backend={self.backend!r}, query={self.query!r}"
        else:
            source = "pem" if self._pem is not None else "identity"
        label = f"{self.name!r}, " if self.name else ""
        return f"Credential({label}{source})"

    @classmethod
    def from_pem(
        cls,
        certificate: Union[str, bytes],
        key: Union[str, bytes, None] = None,
        password: "sslcontext.PasswordSource" = None,
        *,
        name: str = "",
        **context_options: Any,
    ) -> "Credential":
        """A credential from a PEM certificate (+ chain) and key held in
        memory (``key`` omitted: both are in ``certificate``)."""
        return cls(pem=(certificate, key, password), name=name, **context_options)

    def invalidate(self) -> None:
        """Forget the built context; the next use looks the identity up again."""
        with self._lock:
            self._context = None

    def context(self) -> ssl.SSLContext:
        """The client context, built on first call.

        Raises :class:`~netproxy.exceptions.CredentialUnavailableError` when
        the identity cannot be found or loaded.
        """
        with self._lock:
            if self._context is None:
                self._context = self._build()
            return self._context

    def _build(self) -> ssl.SSLContext:
        try:
            context = sslcontext.create_context(**self._context_options)
            if self._pem is not None:
                sslcontext.load_pem(context, *self._pem)
            else:
                sslcontext.load_identity(context, self._resolve())
        except sslcontext.SSLContextError as error:
            raise CredentialUnavailableError(f"{self!r}: {error}") from error
        return context

    def _resolve(self) -> "sslcontext.Identity":
        if self.backend is None:
            identity = self._identity
            return identity() if callable(identity) else identity  # type: ignore[return-value]
        with get_backend(self.backend)(**self.options) as keystore:
            return keystore.find_identity(**self.query)
