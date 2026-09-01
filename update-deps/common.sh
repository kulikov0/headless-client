apply_patch() {
  patch_root="$1"
  patch_file="$2"
  patch_name="$(basename "$patch_file")"
  if patch -p1 -d "$patch_root" -N --dry-run -s < "$patch_file" >/dev/null 2>&1; then
    patch -p1 -d "$patch_root" -N -s < "$patch_file"
    echo "applied $patch_name"
  elif patch -p1 -d "$patch_root" -R --dry-run -s < "$patch_file" >/dev/null 2>&1; then
    echo "skipped $patch_name, already present in the source"
  else
    echo "cannot apply $patch_name" >&2
    exit 1
  fi
}
