test_basic_usage() {
  # import a tarball
  if [ ! -f ubuntu-*.xz ]; then
	  $SRC_DIR/../make_lxc_tarball.sh ubuntu trusty
	  test -f ubuntu-*.xz
  fi
  shasum=`sha256sum ubuntu*.xz | awk '{ print $1 }'`
  lxc image import ubuntu*.xz
  lxc launch $shasum foo
  # should fail if foo isn't running
  lxc stop foo
  lxc delete foo

  lxc init $shasum foo

  # did it get created?
  lxc list | grep foo

  # cycle it a few times
  lxc start foo
  lxc stop foo
  lxc start foo

  # Make sure it is the right version
  lxc exec foo /bin/cat /etc/issue | grep 14.04
  echo foo | lxc exec foo tee /tmp/foo

  # This is why we can't have nice things.
  content=$(cat "${LXD_DIR}/lxc/foo/rootfs/tmp/foo")
  [ "$content" = "foo" ]

  # cleanup
  lxc stop foo
  lxc delete foo
}
