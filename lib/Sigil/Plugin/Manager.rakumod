# Sigil::Plugin::Manager - Dynamic dissector discovery and extension loader
#
# Discovers, verifies, and registers custom user-contributed protocol grammar
# modules at runtime without rebuilding the core engine.

unit class Sigil::Plugin::Manager;

use Sigil::Core::Registry;

has @.search-paths = <plugins custom_dissectors>;
has %!loaded-plugins;                       # Str name => Hash metadata

# Register a plugin module into runtime dissector registry
method load-dissector(Str $module-name --> Bool) {
    try {
        require ::($module-name);
        my $class = ::($module-name);
        my $instance = $class.new;

        # Register instance with dissector registry
        Sigil::Core::Registry.register($instance);

        %!loaded-plugins{$module-name} = {
            name        => $module-name,
            protocol    => $instance.protocol-name,
            status      => "active",
            loaded_at   => now.DateTime.Str
        };
        return True;
    }
    return False;
}

# Scan directory for plugin .rakumod files
method discover-plugins(Str $dir --> List) {
    my @found;
    return @found unless $dir.IO.d;

    for $dir.IO.dir -> $file {
        if $file.extension eq "rakumod" {
            @found.push($file.path);
        }
    }
    return @found;
}

# List all currently active plugins
method loaded-plugins(--> List) {
    return %!loaded-plugins.values.list;
}

# Unload all plugins
method clear() {
    %!loaded-plugins = ();
}
