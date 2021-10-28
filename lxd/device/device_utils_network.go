package device

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"

	deviceConfig "github.com/lxc/lxd/lxd/device/config"
	pcidev "github.com/lxc/lxd/lxd/device/pci"
	"github.com/lxc/lxd/lxd/instance"
	"github.com/lxc/lxd/lxd/instance/instancetype"
	"github.com/lxc/lxd/lxd/ip"
	"github.com/lxc/lxd/lxd/network"
	"github.com/lxc/lxd/lxd/network/openvswitch"
	"github.com/lxc/lxd/lxd/revert"
	"github.com/lxc/lxd/lxd/state"
	"github.com/lxc/lxd/lxd/util"
	"github.com/lxc/lxd/shared"
	"github.com/lxc/lxd/shared/logger"
	"github.com/lxc/lxd/shared/units"
	"github.com/lxc/lxd/shared/validate"
)

// Instances can be started in parallel, so lock the creation of VLANs.
var networkCreateSharedDeviceLock sync.Mutex

// NetworkSetDevMTU sets the MTU setting for a named network device if different from current.
func NetworkSetDevMTU(devName string, mtu uint32) error {
	curMTU, err := network.GetDevMTU(devName)
	if err != nil {
		return err
	}

	// Only try and change the MTU if the requested mac is different to current one.
	if curMTU != mtu {
		link := &ip.Link{Name: devName}
		err := link.SetMTU(fmt.Sprintf("%d", mtu))
		if err != nil {
			return err
		}
	}

	return nil
}

// NetworkGetDevMAC retrieves the current MAC setting for a named network device.
func NetworkGetDevMAC(devName string) (string, error) {
	content, err := ioutil.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", devName))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(fmt.Sprintf("%s", content)), nil
}

// NetworkSetDevMAC sets the MAC setting for a named network device if different from current.
func NetworkSetDevMAC(devName string, mac string) error {
	curMac, err := NetworkGetDevMAC(devName)
	if err != nil {
		return err
	}

	// Only try and change the MAC if the requested mac is different to current one.
	if curMac != mac {
		link := &ip.Link{Name: devName}
		err := link.SetAddress(mac)
		if err != nil {
			return err
		}
	}

	return nil
}

// networkRemoveInterfaceIfNeeded removes a network interface by name but only if no other instance is using it.
func networkRemoveInterfaceIfNeeded(state *state.State, nic string, current instance.Instance, parent string, vlanID string) error {
	// Check if it's used by another instance.
	instances, err := instance.LoadNodeAll(state, instancetype.Any)
	if err != nil {
		return err
	}

	for _, inst := range instances {
		if inst.Name() == current.Name() && inst.Project() == current.Project() {
			continue
		}

		for devName, dev := range inst.ExpandedDevices() {
			if dev["type"] != "nic" || dev["vlan"] != vlanID || dev["parent"] != parent {
				continue
			}

			// Check if another running instance created the device, if so, don't touch it.
			if shared.IsTrue(inst.ExpandedConfig()[fmt.Sprintf("volatile.%s.last_state.created", devName)]) {
				return nil
			}
		}
	}

	return network.InterfaceRemove(nic)
}

// networkCreateVlanDeviceIfNeeded creates a VLAN device if doesn't already exist.
func networkCreateVlanDeviceIfNeeded(state *state.State, parent string, vlanDevice string, vlanID string, gvrp bool) (string, error) {
	if vlanID != "" {
		created, err := network.VLANInterfaceCreate(parent, vlanDevice, vlanID, gvrp)
		if err != nil {
			return "", err
		}

		if created {
			return "created", nil
		}

		// Check if it was created for another running instance.
		instances, err := instance.LoadNodeAll(state, instancetype.Any)
		if err != nil {
			return "", err
		}

		for _, inst := range instances {
			for devName, dev := range inst.ExpandedDevices() {
				if dev["type"] != "nic" || dev["vlan"] != vlanID || dev["parent"] != parent {
					continue
				}

				// Check if another running instance created the device, if so, mark it as created.
				if shared.IsTrue(inst.ExpandedConfig()[fmt.Sprintf("volatile.%s.last_state.created", devName)]) {
					return "reused", nil
				}
			}
		}
	}

	return "existing", nil
}

// networkSnapshotPhysicalNic records properties of the NIC to volatile so they can be restored later.
func networkSnapshotPhysicalNic(hostName string, volatile map[string]string) error {
	// Store current MTU for restoration on detach.
	mtu, err := network.GetDevMTU(hostName)
	if err != nil {
		return err
	}
	volatile["last_state.mtu"] = fmt.Sprintf("%d", mtu)

	// Store current MAC for restoration on detach
	mac, err := NetworkGetDevMAC(hostName)
	if err != nil {
		return err
	}
	volatile["last_state.hwaddr"] = mac
	return nil
}

// networkRestorePhysicalNic restores NIC properties from volatile to what they were before it was attached.
func networkRestorePhysicalNic(hostName string, volatile map[string]string) error {
	// If we created the "physical" device and then it should be removed.
	if shared.IsTrue(volatile["last_state.created"]) {
		return network.InterfaceRemove(hostName)
	}

	// Bring the interface down, as this is sometimes needed to change settings on the nic.
	link := &ip.Link{Name: hostName}
	err := link.SetDown()
	if err != nil {
		return fmt.Errorf("Failed to bring down \"%s\": %v", hostName, err)
	}

	// If MTU value is specified then there is an original MTU that needs restoring.
	if volatile["last_state.mtu"] != "" {
		mtuInt, err := strconv.ParseUint(volatile["last_state.mtu"], 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to convert mtu for \"%s\" mtu \"%s\": %v", hostName, volatile["last_state.mtu"], err)
		}

		err = NetworkSetDevMTU(hostName, uint32(mtuInt))
		if err != nil {
			return fmt.Errorf("Failed to restore physical dev \"%s\" mtu to \"%d\": %v", hostName, mtuInt, err)
		}
	}

	// If MAC value is specified then there is an original MAC that needs restoring.
	if volatile["last_state.hwaddr"] != "" {
		err := NetworkSetDevMAC(hostName, volatile["last_state.hwaddr"])
		if err != nil {
			return fmt.Errorf("Failed to restore physical dev \"%s\" mac to \"%s\": %v", hostName, volatile["last_state.hwaddr"], err)
		}
	}

	return nil
}

// networkCreateVethPair creates and configures a veth pair. It will set the hwaddr and mtu settings
// in the supplied config to the newly created peer interface. If mtu is not specified, but parent
// is supplied in config, then the MTU of the new peer interface will inherit the parent MTU.
// Accepts the name of the host side interface as a parameter and returns the peer interface name.
func networkCreateVethPair(hostName string, m deviceConfig.Device) (string, error) {
	peerName := network.RandomDevName("veth")

	veth := &ip.Veth{
		Link: ip.Link{
			Name: hostName,
		},
		PeerName: peerName,
	}
	err := veth.Add()
	if err != nil {
		return "", fmt.Errorf("Failed to create the veth interfaces %s and %s: %v", hostName, peerName, err)
	}

	err = veth.SetUp()
	if err != nil {
		network.InterfaceRemove(hostName)
		return "", fmt.Errorf("Failed to bring up the veth interface %s: %v", hostName, err)
	}

	// Set the MAC address on peer.
	if m["hwaddr"] != "" {
		link := &ip.Link{Name: peerName}
		err := link.SetAddress(m["hwaddr"])
		if err != nil {
			network.InterfaceRemove(peerName)
			return "", fmt.Errorf("Failed to set the MAC address: %v", err)
		}
	}

	// Set the MTU on peer. If not specified and has parent, will inherit MTU from parent.
	if m["mtu"] != "" {
		mtu, err := strconv.ParseUint(m["mtu"], 10, 32)
		if err != nil {
			return "", fmt.Errorf("Invalid MTU specified: %v", err)
		}

		err = NetworkSetDevMTU(peerName, uint32(mtu))
		if err != nil {
			network.InterfaceRemove(peerName)
			return "", fmt.Errorf("Failed to set the MTU: %v", err)
		}

		err = NetworkSetDevMTU(hostName, uint32(mtu))
		if err != nil {
			network.InterfaceRemove(peerName)
			return "", fmt.Errorf("Failed to set the MTU: %v", err)
		}
	} else if m["parent"] != "" {
		parentMTU, err := network.GetDevMTU(m["parent"])
		if err != nil {
			return "", fmt.Errorf("Failed to get the parent MTU: %v", err)
		}

		err = NetworkSetDevMTU(peerName, parentMTU)
		if err != nil {
			network.InterfaceRemove(peerName)
			return "", fmt.Errorf("Failed to set the MTU: %v", err)
		}

		err = NetworkSetDevMTU(hostName, parentMTU)
		if err != nil {
			network.InterfaceRemove(peerName)
			return "", fmt.Errorf("Failed to set the MTU: %v", err)
		}
	}

	return peerName, nil
}

// networkCreateTap creates and configures a TAP device.
func networkCreateTap(hostName string, m deviceConfig.Device) error {
	tuntap := &ip.Tuntap{
		Name:       hostName,
		Mode:       "tap",
		MultiQueue: true,
	}
	err := tuntap.Add()
	if err != nil {
		return errors.Wrapf(err, "Failed to create the tap interfaces %s", hostName)
	}

	revert := revert.New()
	defer revert.Fail()

	link := &ip.Link{Name: hostName}
	err = link.SetUp()
	if err != nil {
		return errors.Wrapf(err, "Failed to bring up the tap interface %s", hostName)
	}
	revert.Add(func() { network.InterfaceRemove(hostName) })

	// Set the MTU on peer. If not specified and has parent, will inherit MTU from parent.
	if m["mtu"] != "" {
		mtu, err := strconv.ParseUint(m["mtu"], 10, 32)
		if err != nil {
			return errors.Wrap(err, "Invalid MTU specified")
		}

		err = NetworkSetDevMTU(hostName, uint32(mtu))
		if err != nil {
			return errors.Wrap(err, "Failed to set the MTU")
		}
	} else if m["parent"] != "" {
		parentMTU, err := network.GetDevMTU(m["parent"])
		if err != nil {
			return errors.Wrap(err, "Failed to get the parent MTU")
		}

		err = NetworkSetDevMTU(hostName, parentMTU)
		if err != nil {
			return errors.Wrap(err, "Failed to set the MTU")
		}
	}

	revert.Success()
	return nil
}

// networkVethFillFromVolatile fills veth host_name and hwaddr fields from volatile if not set in device config.
func networkVethFillFromVolatile(device deviceConfig.Device, volatile map[string]string) {
	// If not configured, check if volatile data contains the most recently added host_name.
	if device["host_name"] == "" {
		device["host_name"] = volatile["host_name"]
	}

	// If not configured, check if volatile data contains the most recently added hwaddr.
	if device["hwaddr"] == "" {
		device["hwaddr"] = volatile["hwaddr"]
	}
}

// networkNICRouteAdd applies any static host-side routes configured for an instance NIC.
func networkNICRouteAdd(routeDev string, routes ...string) error {
	if !network.InterfaceExists(routeDev) {
		return fmt.Errorf("Route interface missing %q", routeDev)
	}

	revert := revert.New()
	defer revert.Fail()

	for _, r := range routes {
		route := r // Local var for revert.
		ipAddress, _, err := net.ParseCIDR(route)
		if err != nil {
			return errors.Wrapf(err, "Invalid route %q", route)
		}

		ipVersion := ip.FamilyV4
		if ipAddress.To4() == nil {
			ipVersion = ip.FamilyV6
		}

		// Add IP route (using boot proto to avoid conflicts with network defined static routes).
		r := &ip.Route{
			DevName: routeDev,
			Route:   route,
			Proto:   "boot",
			Family:  ipVersion,
		}
		err = r.Add()
		if err != nil {
			return err
		}

		revert.Add(func() {
			r := &ip.Route{
				DevName: routeDev,
				Route:   route,
				Proto:   "boot",
				Family:  ipVersion,
			}
			r.Flush()
		})
	}

	revert.Success()
	return nil
}

// networkNICRouteDelete deletes any static host-side routes configured for an instance NIC.
// Logs any errors and continues to next route to remove.
func networkNICRouteDelete(routeDev string, routes ...string) {
	if routeDev == "" {
		logger.Errorf("Failed removing static route, empty route device specified")
		return
	}

	if !network.InterfaceExists(routeDev) {
		return //Routes will already be gone if device doesn't exist.
	}

	for _, r := range routes {
		route := r // Local var for revert.
		ipAddress, _, err := net.ParseCIDR(route)
		if err != nil {
			logger.Errorf("Failed to remove static route %q to %q: %v", route, routeDev, err)
			continue
		}

		ipVersion := ip.FamilyV4
		if ipAddress.To4() == nil {
			ipVersion = ip.FamilyV6
		}

		// Add IP route (using boot proto to avoid conflicts with network defined static routes).
		r := &ip.Route{
			DevName: routeDev,
			Route:   route,
			Proto:   "boot",
			Family:  ipVersion,
		}
		r.Flush()
		if err != nil {
			logger.Errorf("Failed to remove static route %q to %q: %v", route, routeDev, err)
			continue
		}
	}
}

// networkSetupHostVethLimits applies any network rate limits to the veth device specified in the config.
func networkSetupHostVethLimits(m deviceConfig.Device) error {
	var err error

	veth := m["host_name"]

	if veth == "" || !network.InterfaceExists(veth) {
		return fmt.Errorf("Unknown or missing host side veth device %q", veth)
	}

	// Apply max limit
	if m["limits.max"] != "" {
		m["limits.ingress"] = m["limits.max"]
		m["limits.egress"] = m["limits.max"]
	}

	// Parse the values
	var ingressInt int64
	if m["limits.ingress"] != "" {
		ingressInt, err = units.ParseBitSizeString(m["limits.ingress"])
		if err != nil {
			return err
		}
	}

	var egressInt int64
	if m["limits.egress"] != "" {
		egressInt, err = units.ParseBitSizeString(m["limits.egress"])
		if err != nil {
			return err
		}
	}

	// Clean any existing entry
	qdisc := &ip.Qdisc{Dev: veth, Root: true}
	qdisc.Delete()
	qdisc = &ip.Qdisc{Dev: veth, Ingress: true}
	qdisc.Delete()

	// Apply new limits
	if m["limits.ingress"] != "" {
		qdiscHTB := &ip.QdiscHTB{Qdisc: ip.Qdisc{Dev: veth, Handle: "1:0", Root: true}, Default: "10"}
		err := qdiscHTB.Add()
		if err != nil {
			return fmt.Errorf("Failed to create root tc qdisc: %s", err)
		}

		classHTB := &ip.ClassHTB{Class: ip.Class{Dev: veth, Parent: "1:0", Classid: "1:10"}, Rate: fmt.Sprintf("%dbit", ingressInt)}
		err = classHTB.Add()
		if err != nil {
			return fmt.Errorf("Failed to create limit tc class: %s", err)
		}

		filter := &ip.U32Filter{Filter: ip.Filter{Dev: veth, Parent: "1:0", Protocol: "all", Flowid: "1:1"}, Value: "0", Mask: "0"}
		err = filter.Add()
		if err != nil {
			return fmt.Errorf("Failed to create tc filter: %s", err)
		}
	}

	if m["limits.egress"] != "" {
		qdisc = &ip.Qdisc{Dev: veth, Handle: "ffff:0", Ingress: true}
		err := qdisc.Add()
		if err != nil {
			return fmt.Errorf("Failed to create ingress tc qdisc: %s", err)
		}

		police := &ip.ActionPolice{Rate: fmt.Sprintf("%dbit", egressInt), Burst: "1024k", Mtu: "64kb", Drop: true}
		filter := &ip.U32Filter{Filter: ip.Filter{Dev: veth, Parent: "ffff:0", Protocol: "all"}, Value: "0", Mask: "0", Actions: []ip.Action{police}}
		err = filter.Add()
		if err != nil {
			return fmt.Errorf("Failed to create ingress tc filter: %s", err)
		}
	}

	return nil
}

// networkValidGateway validates the gateway value.
func networkValidGateway(value string) error {
	if shared.StringInSlice(value, []string{"none", "auto"}) {
		return nil
	}

	return fmt.Errorf("Invalid gateway: %s", value)
}

// networkValidVLANList validates a comma delimited list of VLAN IDs.
func networkValidVLANList(value string) error {
	for _, vlanID := range strings.Split(value, ",") {
		vlanID = strings.TrimSpace(vlanID)
		err := validate.IsNetworkVLAN(vlanID)
		if err != nil {
			return err
		}
	}

	return nil
}

// bgpAddPrefix adds external routes to the BGP server.
func bgpAddPrefix(d *deviceCommon, n network.Network, config map[string]string) error {
	// BGP is only valid when tied to a managed network.
	if config["network"] == "" {
		return nil
	}

	// Parse nexthop configuration.
	nexthopV4 := net.ParseIP(n.Config()["bgp.ipv4.nexthop"])
	if nexthopV4 == nil {
		nexthopV4 = net.ParseIP(n.Config()["volatile.network.ipv4.address"])
		if nexthopV4 == nil {
			nexthopV4 = net.ParseIP("0.0.0.0")
		}
	}

	nexthopV6 := net.ParseIP(n.Config()["bgp.ipv6.nexthop"])
	if nexthopV6 == nil {
		nexthopV6 = net.ParseIP(n.Config()["volatile.network.ipv6.address"])
		if nexthopV6 == nil {
			nexthopV6 = net.ParseIP("::")
		}
	}

	// Add the prefixes.
	bgpOwner := fmt.Sprintf("instance_%d_%s", d.inst.ID(), d.name)
	if config["ipv4.routes.external"] != "" {
		for _, prefix := range util.SplitNTrimSpace(config["ipv4.routes.external"], ",", -1, true) {
			_, prefixNet, err := net.ParseCIDR(prefix)
			if err != nil {
				return err
			}

			err = d.state.BGP.AddPrefix(*prefixNet, nexthopV4, bgpOwner)
			if err != nil {
				return err
			}
		}
	}

	if config["ipv6.routes.external"] != "" {
		for _, prefix := range util.SplitNTrimSpace(config["ipv6.routes.external"], ",", -1, true) {
			_, prefixNet, err := net.ParseCIDR(prefix)
			if err != nil {
				return err
			}

			err = d.state.BGP.AddPrefix(*prefixNet, nexthopV6, bgpOwner)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func bgpRemovePrefix(d *deviceCommon, config map[string]string) error {
	// BGP is only valid when tied to a managed network.
	if config["network"] == "" {
		return nil
	}

	// Load the network configuration.
	err := d.state.BGP.RemovePrefixByOwner(fmt.Sprintf("instance_%d_%s", d.inst.ID(), d.name))
	if err != nil {
		return err
	}

	return nil
}

func networkValidAcceleration(value string) error {
	err := validate.IsOneOf("none", "sriov")(value)
	if err != nil {
		return err
	}

	if value == "sriov" {
		ovs := openvswitch.NewOVS()

		if !ovs.HardwareOffloadingEnabled() {
			return errors.New("acceleration=sriov cannot be used if hardware offloading is disabled")
		}
	}

	return nil
}

func networkSetupContainerVF(name string, config map[string]string) error {
	// Set the MAC address.
	if config["hwaddr"] != "" {
		link := &ip.Link{Name: name}
		err := link.SetAddress(config["hwaddr"])
		if err != nil {
			return errors.Wrapf(err, "Failed setting MAC address %q on %q", config["hwaddr"], name)
		}
	}

	// Set the MTU.
	if config["mtu"] != "" {
		link := &ip.Link{Name: name}
		err := link.SetMTU(config["mtu"])
		if err != nil {
			return errors.Wrapf(err, "Failed setting MTU %q on %q", config["mtu"], name)
		}
	}

	// Bring the interface up.
	link := &ip.Link{Name: name}
	err := link.SetUp()
	if err != nil {
		if config["hwaddr"] != "" {
			return errors.Wrapf(err, "Failed to bring up VF interface %q", name)
		}

		upErr := err

		// If interface fails to come up and MAC not previously set, some NICs require us to set
		// a specific MAC before being allowed to bring up the VF interface. So check if interface
		// has an empty MAC and set a random one if needed.
		vfIF, err := net.InterfaceByName(name)
		if err != nil {
			return errors.Wrapf(err, "Failed getting interface info for VF %q", name)
		}

		// If the VF interface has a MAC already, something else prevented bringing interface up.
		if vfIF.HardwareAddr.String() != "00:00:00:00:00:00" {
			return errors.Wrapf(upErr, "Failed to bring up VF interface %q", name)
		}

		// Try using a random MAC address and bringing interface up.
		randMAC, err := instance.DeviceNextInterfaceHWAddr()
		if err != nil {
			return errors.Wrapf(err, "Failed generating random MAC for VF %q", name)
		}

		link := &ip.Link{Name: name}
		err = link.SetAddress(randMAC)
		if err != nil {
			return errors.Wrapf(err, "Failed to set random MAC address %q on %q", randMAC, name)
		}

		err = link.SetUp()
		if err != nil {
			return errors.Wrapf(err, "Failed to bring up VF interface %q", name)
		}
	}

	return nil
}

// networkSetupSriovParent configures a SR-IOV virtual function (VF) device on parent and stores original properties of
// the physical device into voltatile for restoration on detach. Returns VF PCI device info and IOMMU group number
// for VMs.
func networkSetupSriovParent(d deviceCommon, vfParent string, vfDevice string, vfID int, volatile map[string]string) (pcidev.Device, uint64, error) {
	var vfPCIDev pcidev.Device

	// Retrieve VF settings from parent device.
	vfInfo, err := networkGetVirtFuncInfo(vfParent, vfID)
	if err != nil {
		return vfPCIDev, 0, err
	}

	revert := revert.New()
	defer revert.Fail()

	// Record properties of VF settings on the parent device.
	volatile["last_state.vf.hwaddr"] = vfInfo.Address
	volatile["last_state.vf.id"] = fmt.Sprintf("%d", vfID)
	volatile["last_state.vf.vlan"] = fmt.Sprintf("%d", vfInfo.VLANs[0]["vlan"])
	volatile["last_state.vf.spoofcheck"] = fmt.Sprintf("%t", vfInfo.SpoofCheck)

	// Record the host interface we represents the VF device which we will move into instance.
	volatile["host_name"] = vfDevice
	volatile["last_state.created"] = "false" // Indicates don't delete device at stop time.

	// Record properties of VF device.
	err = networkSnapshotPhysicalNic(volatile["host_name"], volatile)
	if err != nil {
		return vfPCIDev, 0, err
	}

	// Get VF device's PCI Slot Name so we can unbind and rebind it from the host.
	vfPCIDev, err = network.SRIOVGetVFDevicePCISlot(vfParent, volatile["last_state.vf.id"])
	if err != nil {
		return vfPCIDev, 0, err
	}

	// Unbind VF device from the host so that the settings will take effect when we rebind it.
	err = pcidev.DeviceUnbind(vfPCIDev)
	if err != nil {
		return vfPCIDev, 0, err
	}

	revert.Add(func() { pcidev.DeviceProbe(vfPCIDev) })

	// Setup VF VLAN if specified.
	if d.config["vlan"] != "" {
		link := &ip.Link{Name: vfParent}
		err := link.SetVfVlan(volatile["last_state.vf.id"], d.config["vlan"])
		if err != nil {
			return vfPCIDev, 0, err
		}
	}

	// Setup VF MAC spoofing protection if specified.
	// The ordering of this section is very important, as Intel cards require a very specific
	// order of setup to allow LXD to set custom MACs when using spoof check mode.
	if shared.IsTrue(d.config["security.mac_filtering"]) {
		// If no MAC specified in config, use current VF interface MAC.
		mac := d.config["hwaddr"]
		if mac == "" {
			mac = volatile["last_state.hwaddr"]
		}

		// Set MAC on VF (this combined with spoof checking prevents any other MAC being used).
		link := &ip.Link{Name: vfParent}
		err = link.SetVfAddress(volatile["last_state.vf.id"], mac)
		if err != nil {
			return vfPCIDev, 0, err
		}

		// Now that MAC is set on VF, we can enable spoof checking.
		err = link.SetVfSpoofchk(volatile["last_state.vf.id"], "on")
		if err != nil {
			return vfPCIDev, 0, err
		}
	} else {
		// Try to reset VF to ensure no previous MAC restriction exists, as some devices require this
		// before being able to set a new VF MAC or disable spoofchecking. However some devices don't
		// allow it so ignore failures.
		link := &ip.Link{Name: vfParent}
		err = link.SetVfAddress(volatile["last_state.vf.id"], "00:00:00:00:00:00")
		if err != nil {
			return vfPCIDev, 0, err
		}

		if d.config["parent"] == vfParent {
			// Ensure spoof checking is disabled if not enabled in instance (only for real VF).
			err = link.SetVfSpoofchk(volatile["last_state.vf.id"], "off")
			if err != nil {
				return vfPCIDev, 0, err
			}
		}

		// Set MAC on VF if specified (this should be passed through into VM when it is bound to vfio-pci).
		if d.inst.Type() == instancetype.VM {
			// If no MAC specified in config, use current VF interface MAC.
			mac := d.config["hwaddr"]
			if mac == "" {
				mac = volatile["last_state.hwaddr"]
			}

			err = link.SetVfAddress(volatile["last_state.vf.id"], mac)
			if err != nil {
				return vfPCIDev, 0, err
			}
		}
	}

	// pciIOMMUGroup, used for VM physical passthrough.
	var pciIOMMUGroup uint64

	if d.inst.Type() == instancetype.Container {
		// Bind VF device onto the host so that the settings will take effect.
		// This will remove the VF interface temporarily, and it will re-appear shortly after.
		err = pcidev.DeviceProbe(vfPCIDev)
		if err != nil {
			return vfPCIDev, 0, err
		}

		// Wait for VF driver to be reloaded. Unfortunately the time between sending the bind event
		// to the nic and it actually appearing on the host is non-zero, so we need to watch and wait,
		// otherwise next steps of applying settings to interface will fail.
		err = network.InterfaceBindWait(volatile["host_name"])
		if err != nil {
			return vfPCIDev, 0, err
		}
	} else if d.inst.Type() == instancetype.VM {
		pciIOMMUGroup, err = pcidev.DeviceIOMMUGroup(vfPCIDev.SlotName)
		if err != nil {
			return vfPCIDev, 0, err
		}

		// Register VF device with vfio-pci driver so it can be passed to VM.
		err = pcidev.DeviceDriverOverride(vfPCIDev, "vfio-pci")
		if err != nil {
			return vfPCIDev, 0, err
		}

		// Record original driver used by VF device for restore.
		volatile["last_state.pci.driver"] = vfPCIDev.Driver
	}

	revert.Success()
	return vfPCIDev, pciIOMMUGroup, nil
}

// networkGetVirtFuncInfo returns info about an SR-IOV virtual function from the ip tool.
func networkGetVirtFuncInfo(devName string, vfID int) (ip.VirtFuncInfo, error) {
	link := &ip.Link{Name: devName}
	vfi, err := link.GetVFInfo(vfID)
	return vfi, err
}

// networkRestoreSriovParent restores SR-IOV parent device settings when removed from an instance using the
// volatile data that was stored when the device was first added with setupSriovParent().
func networkRestoreSriovParent(d deviceCommon, volatile map[string]string) error {
	// Nothing to do if we don't know the original device name or the VF ID.
	if volatile["host_name"] == "" || volatile["last_state.vf.id"] == "" || d.config["parent"] == "" {
		return nil
	}

	revert := revert.New()
	defer revert.Fail()

	// Get VF device's PCI info so we can unbind and rebind it from the host.
	vfPCIDev, err := network.SRIOVGetVFDevicePCISlot(d.config["parent"], volatile["last_state.vf.id"])
	if err != nil {
		return err
	}

	// Unbind VF device from the host so that the restored settings will take effect when we rebind it.
	err = pcidev.DeviceUnbind(vfPCIDev)
	if err != nil {
		return err
	}

	if d.inst.Type() == instancetype.VM {
		// Before we bind the device back to the host, ensure we restore the original driver info as it
		// should be currently set to vfio-pci.
		err = pcidev.DeviceSetDriverOverride(vfPCIDev, volatile["last_state.pci.driver"])
		if err != nil {
			return err
		}
	}

	// However we return from this function, we must try to rebind the VF so its not orphaned.
	// The OS won't let an already bound device be bound again so is safe to call twice.
	revert.Add(func() { pcidev.DeviceProbe(vfPCIDev) })

	// Reset VF VLAN if specified
	if volatile["last_state.vf.vlan"] != "" {
		link := &ip.Link{Name: d.config["parent"]}
		err := link.SetVfVlan(volatile["last_state.vf.id"], volatile["last_state.vf.vlan"])
		if err != nil {
			return err
		}
	}

	// Reset VF MAC spoofing protection if recorded. Do this first before resetting the MAC
	// to avoid any issues with zero MACs refusing to be set whilst spoof check is on.
	if volatile["last_state.vf.spoofcheck"] != "" {
		mode := "off"
		if shared.IsTrue(volatile["last_state.vf.spoofcheck"]) {
			mode = "on"
		}

		link := &ip.Link{Name: d.config["parent"]}
		err := link.SetVfSpoofchk(volatile["last_state.vf.id"], mode)
		if err != nil {
			return err
		}
	}

	// Reset VF MAC specified if specified.
	if volatile["last_state.vf.hwaddr"] != "" {
		link := &ip.Link{Name: d.config["parent"]}
		err := link.SetVfAddress(volatile["last_state.vf.id"], volatile["last_state.vf.hwaddr"])
		if err != nil {
			return err
		}
	}

	// Bind VF device onto the host so that the settings will take effect.
	err = pcidev.DeviceProbe(vfPCIDev)
	if err != nil {
		return err
	}

	// Wait for VF driver to be reloaded, this will remove the VF interface from the instance
	// and it will re-appear on the host. Unfortunately the time between sending the bind event
	// to the nic and it actually appearing on the host is non-zero, so we need to watch and wait,
	// otherwise next step of restoring MAC and MTU settings in restorePhysicalNic will fail.
	err = network.InterfaceBindWait(volatile["host_name"])
	if err != nil {
		return err
	}

	// Restore VF interface settings.
	err = networkRestorePhysicalNic(volatile["host_name"], volatile)
	if err != nil {
		return err
	}

	revert.Success()
	return nil
}
