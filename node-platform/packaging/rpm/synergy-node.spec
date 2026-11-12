Name: synergy-node
Version: 0.1.0
Release: 1%{?dist}
Summary: Universal Synergy Network node
License: Apache-2.0
%description
Universal Synergy Network node runtime.
%install
install -D -m0755 synergy-node %{buildroot}%{_bindir}/synergy-node
%files
%{_bindir}/synergy-node
