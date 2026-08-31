{
  description = "Exact cargo-deny package for the final supported Intel macOS Nixpkgs line";

  # Nixpkgs 26.11 dropped x86_64-darwin, while the final supported 26.05
  # package set carries cargo-deny 0.19.6. Keep the build platform on the
  # supported Nixpkgs line, but build the current pinned cargo-deny release
  # from its immutable upstream source and dependency hashes.
  inputs.nixpkgs.url =
    "github:NixOS/nixpkgs/f6107e546a5012172d93e79f1f7950da02ad798f";

  outputs = { nixpkgs, ... }: {
    packages.x86_64-darwin.cargo-deny =
      nixpkgs.legacyPackages.x86_64-darwin.callPackage ./package.nix { };
  };
}
