package intel

import (
	"regexp"
	"sort"
	"strings"
)

// product es un software conocido con los nombres con que lo publican las distintas fuentes.
type product struct {
	ID    string
	Names []string // como lo nombran Shodan, el registro CVE o el fabricante (normalizados)
	CPEs  []string // vendor:product en el diccionario CPE
	EOL   string   // identificador en endoflife.date
}

var catalog = []product{
	{ID: "openssh", Names: []string{"openssh"}, CPEs: []string{"openbsd:openssh"}},
	{ID: "apache-httpd", Names: []string{"apache httpd", "apache http server", "http server", "httpd"}, CPEs: []string{"apache:http_server"}, EOL: "apache-http-server"},
	{ID: "nginx", Names: []string{"nginx", "nginx web server"}, CPEs: []string{"f5:nginx", "nginx:nginx", "f5:nginx_open_source"}, EOL: "nginx"},
	{ID: "iis", Names: []string{"microsoft iis httpd", "internet information services", "iis"}, CPEs: []string{"microsoft:internet_information_services", "microsoft:iis"}},
	{ID: "tomcat", Names: []string{"apache tomcat", "tomcat", "apache tomcat coyote jsp engine"}, CPEs: []string{"apache:tomcat"}, EOL: "tomcat"},
	{ID: "php", Names: []string{"php"}, CPEs: []string{"php:php", "php_group:php"}, EOL: "php"},
	{ID: "exim", Names: []string{"exim", "exim smtpd"}, CPEs: []string{"exim:exim"}},
	{ID: "postfix", Names: []string{"postfix", "postfix smtpd"}, CPEs: []string{"postfix:postfix"}},
	{ID: "dovecot", Names: []string{"dovecot", "dovecot pop3d", "dovecot imapd"}, CPEs: []string{"dovecot:dovecot"}},
	{ID: "proftpd", Names: []string{"proftpd"}, CPEs: []string{"proftpd:proftpd"}},
	{ID: "vsftpd", Names: []string{"vsftpd"}, CPEs: []string{"beasts:vsftpd", "vsftpd_project:vsftpd"}},
	{ID: "openssl", Names: []string{"openssl"}, CPEs: []string{"openssl:openssl"}},
	{ID: "redis", Names: []string{"redis", "redis key value store"}, CPEs: []string{"redis:redis", "redislabs:redis"}, EOL: "redis"},
	{ID: "mysql", Names: []string{"mysql"}, CPEs: []string{"oracle:mysql", "mysql:mysql"}, EOL: "mysql"},
	{ID: "mariadb", Names: []string{"mariadb"}, CPEs: []string{"mariadb:mariadb"}, EOL: "mariadb"},
	{ID: "postgresql", Names: []string{"postgresql"}, CPEs: []string{"postgresql:postgresql"}, EOL: "postgresql"},
	{ID: "mongodb", Names: []string{"mongodb"}, CPEs: []string{"mongodb:mongodb"}, EOL: "mongodb"},
	{ID: "elasticsearch", Names: []string{"elasticsearch", "elastic elasticsearch"}, CPEs: []string{"elastic:elasticsearch", "elasticsearch:elasticsearch"}, EOL: "elasticsearch"},
	{ID: "grafana", Names: []string{"grafana"}, CPEs: []string{"grafana:grafana"}, EOL: "grafana"},
	{ID: "activemq", Names: []string{"apache activemq", "activemq"}, CPEs: []string{"apache:activemq"}},
	{ID: "exchange", Names: []string{"microsoft exchange", "exchange server", "microsoft exchange server"}, CPEs: []string{"microsoft:exchange_server"}},
	{ID: "fortios", Names: []string{"fortios", "fortinet fortigate ssl vpn", "fortigate"}, CPEs: []string{"fortinet:fortios"}},
	{ID: "pan-os", Names: []string{"pan os", "palo alto networks pan os", "globalprotect"}, CPEs: []string{"paloaltonetworks:pan-os"}},
	{ID: "ios-xe", Names: []string{"cisco ios xe software", "cisco ios xe", "ios xe"}, CPEs: []string{"cisco:ios_xe"}},
	{ID: "big-ip", Names: []string{"big ip", "f5 big ip"}, CPEs: []string{"f5:big-ip_local_traffic_manager", "f5:big-ip_access_policy_manager"}},
	{ID: "confluence", Names: []string{"confluence", "confluence server", "confluence data center"}, CPEs: []string{"atlassian:confluence_server", "atlassian:confluence_data_center"}},
	{ID: "jenkins", Names: []string{"jenkins"}, CPEs: []string{"jenkins:jenkins"}},
	{ID: "gitlab", Names: []string{"gitlab"}, CPEs: []string{"gitlab:gitlab"}},
}

var (
	byName = map[string]string{}
	byCPE  = map[string]string{}
	eolOf  = map[string]string{}
	nonAZ  = regexp.MustCompile(`[^a-z0-9]+`)
)

func init() {
	for _, p := range catalog {
		for _, n := range p.Names {
			byName[norm(n)] = p.ID
		}
		for _, c := range p.CPEs {
			byCPE[c] = p.ID
		}
		if p.EOL != "" {
			eolOf[p.ID] = p.EOL
		}
	}
}

func norm(s string) string { return strings.TrimSpace(nonAZ.ReplaceAllString(strings.ToLower(s), " ")) }

// CPE es la parte util de un identificador CPE 2.2 o 2.3.
type CPE struct{ Part, Vendor, Product, Version string }

// ParseCPE entiende "cpe:2.3:a:apache:http_server:2.4.49:*:…" y "cpe:/a:apache:http_server:2.4.49".
func ParseCPE(s string) (CPE, bool) {
	var f []string
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		f = strings.Split(s[len("cpe:2.3:"):], ":")
	case strings.HasPrefix(s, "cpe:/"):
		f = strings.Split(s[len("cpe:/"):], ":")
	default:
		return CPE{}, false
	}
	if len(f) < 3 {
		return CPE{}, false
	}
	c := CPE{Part: f[0], Vendor: f[1], Product: f[2]}
	if len(f) > 3 && f[3] != "*" && f[3] != "-" {
		c.Version = strings.ReplaceAll(f[3], `\`, "")
	}
	return c, true
}

// key es vendor:product.
func (c CPE) key() string { return c.Vendor + ":" + c.Product }

// Identify reconoce el producto a partir de nombres y CPE. Si no esta en el catalogo, usa el CPE o el
// nombre normalizado como identificador, para que igual se puedan cruzar fuentes.
func Identify(names, cpes []string) []string {
	set := map[string]bool{}
	for _, raw := range cpes {
		if c, ok := ParseCPE(raw); ok {
			if id := byCPE[c.key()]; id != "" {
				set[id] = true
			} else {
				set["cpe:"+c.key()] = true
			}
		}
	}
	for _, n := range names {
		n = norm(n)
		if n == "" || n == "n a" || n == "unspecified" {
			continue
		}
		if id := byName[n]; id != "" {
			set[id] = true
			continue
		}
		// "Fortinet FortiOS, FortiProxy" o "Apache Tomcat 9": buscar nombres conocidos como palabras enteras.
		found := false
		padded := " " + n + " "
		for alias, id := range byName {
			if len(alias) >= 3 && strings.Contains(padded, " "+alias+" ") {
				set[id] = true
				found = true
			}
		}
		if !found && len(cpes) == 0 {
			set["name:"+n] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// cpeKeysFor devuelve los vendor:product con que se busca un producto en la NVD.
func cpeKeysFor(id string) []string {
	if strings.HasPrefix(id, "cpe:") {
		return []string{strings.TrimPrefix(id, "cpe:")}
	}
	for _, p := range catalog {
		if p.ID == id {
			return p.CPEs
		}
	}
	return nil
}

// Distro es un indicio de que el software viene empaquetado por una distribucion, que suele corregir
// vulnerabilidades sin cambiar la version de origen ("backport").
type Distro struct{ Name, Package string }

var (
	reUbuntu = regexp.MustCompile(`(?i)ubuntu[-_ ]?([0-9][\w.~+]*ubuntu[\w.~+]*)`)
	reDebian = regexp.MustCompile(`(?i)(?:debian[-_ ]([0-9][\w.~+]*)|([0-9][\w.~+]*deb[0-9]+u[0-9]+[\w.~+]*))`)
	reRHEL   = regexp.MustCompile(`(?i)[.\-](el[0-9]+(?:_[0-9]+)?)\b`)
	reParen  = regexp.MustCompile(`\((ubuntu|debian|centos|red hat[^)]*|rhel|amazon linux|almalinux|rocky linux|suse|fedora)\)`)
)

// DetectDistro busca en la version y el banner pistas de un paquete de distribucion.
func DetectDistro(version, banner string) *Distro {
	s := version + " " + banner
	if m := reUbuntu.FindStringSubmatch(s); m != nil {
		return &Distro{Name: "Ubuntu", Package: m[1]}
	}
	if m := reDebian.FindStringSubmatch(s); m != nil {
		return &Distro{Name: "Debian", Package: m[1] + m[2]}
	}
	if m := reRHEL.FindStringSubmatch(s); m != nil {
		return &Distro{Name: "Red Hat / derivadas", Package: m[1]}
	}
	if m := reParen.FindStringSubmatch(strings.ToLower(s)); m != nil {
		name := m[1]
		switch {
		case name == "ubuntu":
			name = "Ubuntu"
		case name == "debian":
			name = "Debian"
		case name == "centos", name == "rhel", strings.HasPrefix(name, "red hat"):
			name = "Red Hat / derivadas"
		default:
			name = strings.ToUpper(name[:1]) + name[1:]
		}
		return &Distro{Name: name}
	}
	return nil
}
