"use strict";
"require rpc";
"require form";
"require network";

var callFileList = rpc.declare({
  object: "file",
  method: "list",
  params: ["path"],
  expect: { entries: [] },
  filter: function (list, params) {
    var rv = [];
    for (var i = 0; i < list.length; i++)
      if (list[i].name.match(/^ttyACM/)) rv.push(params.path + list[i].name);
    return rv.sort();
  },
});

network.registerPatternVirtual(/^xmm-.+$/);

return network.registerProtocol("xmm", {
  getI18n: function () {
    return _("Intel XMM Cellular");
  },

  getIfname: function () {
    return this._ubus("l3_device") || "xmm-%s".format(this.sid);
  },

  getOpkgPackage: function () {
    return "xmm-modem";
  },

  isFloating: function () {
    return true;
  },

  isVirtual: function () {
    return true;
  },

  getDevices: function () {
    return null;
  },

  containsDevice: function (ifname) {
    return network.getIfnameOf(ifname) == this.getIfname();
  },

  renderFormOptions: function (s) {
    var dev = this.getL3Device() || this.getDevice(),
      o;

    o = s.taboption("general", form.Value, "device", _("Modem port"));
    o.ucioption = "device";
    o.rmempty = false;
    o.load = function (section_id) {
      return callFileList("/dev/").then(
        L.bind(function (devices) {
          for (var i = 0; i < devices.length; i++) this.value(devices[i]);
          return form.Value.prototype.load.apply(this, [section_id]);
        }, this)
      );
    };

    o = s.taboption("general", form.Value, "apn", _("APN"));
    o.validate = function (section_id, value) {
      if (value == null || value == "") return true;

      if (!/^[a-zA-Z0-9\-.]*[a-zA-Z0-9]$/.test(value))
        return _("Invalid APN provided");

      return true;
    };
    o.placeholder = "internet";

    o = s.taboption("general", form.ListValue, "auth", _("Auth Type"));
    o.value("none", "None");
    o.value("pap", "PAP");
    o.value("chap", "CHAP");
    o.default = "none";

    o = s.taboption("general", form.Value, "username", _("PAP/CHAP username"));
    o.depends("auth", "pap");
    o.depends("auth", "chap");

    o = s.taboption("general", form.Value, "password", _("PAP/CHAP password"));
    o.depends("auth", "pap");
    o.depends("auth", "chap");
    o.password = true;

    o = s.taboption("general", form.ListValue, "pdp", _("PDP Type"));
    o.value("ip", "IPv4");
    o.value("ipv4v6", "IPv4/IPv6");
    o.value("ipv6", "IPv6");
    o.default = "ip";

    o = s.taboption("general", form.Value, "cid", _("PDP Context"));
    o.placeholder = "1";
    o.datatype = "min(0)";

    // ------tab advanced-------

    o = s.taboption(
      "advanced",
      form.Flag,
      "autorc",
      _("Auto reconnection"),
      _("Enable auto reconnection when modem IP losts")
    );
    o.default = o.enabled;

    o = s.taboption(
      "advanced",
      form.Flag,
      "synctime",
      _("Sync time"),
      _("Sync system time with network time")
    );
    o.default = o.enabled;

    o = s.taboption(
      "advanced",
      form.Flag,
      "defaultroute",
      _("Use default gateway"),
      _("If unchecked, no default route is configured")
    );
    o.default = o.enabled;

    o = s.taboption(
      "advanced",
      form.Value,
      "delay",
      _("Modem init timeout"),
      _("Amount of seconds to wait for the modem to become ready")
    );
    o.placeholder = "5";
    o.datatype = "min(0)";

    o = s.taboption("advanced", form.Value, "mtu", _("Override MTU"));
    o.placeholder = dev ? dev.getMTU() || "1500" : "1500";
    o.datatype = "max(9200)";

    o = s.taboption(
      "advanced",
      form.Flag,
      "peerdns",
      _("Use DNS servers advertised by peer"),
      _("If unchecked, the advertised DNS server addresses are ignored")
    );
    o.default = o.enabled;

    o = s.taboption(
      "advanced",
      form.DynamicList,
      "dns",
      _("Use custom DNS servers")
    );
    o.depends("peerdns", "0");
    o.datatype = "ipaddr";

    o = s.taboption("advanced", form.Value, "metric", _("Use gateway metric"));
    o.datatype = "uinteger";
    o.placeholder = "0";
  },
});
