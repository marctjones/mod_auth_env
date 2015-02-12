mod_auth_fake.la: mod_auth_fake.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_auth_fake.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_auth_fake.la
