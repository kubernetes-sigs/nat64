# List of subdirectories used for global "make build", "make clean", etc
SUBDIRS := bpf

# Filter out any directories where the parent directory is also present, to avoid
# building or cleaning a subdirectory twice.
# For example: The directory "tools" is transformed into a match pattern "tools/%",
# which is then used to filter out items such as "tools/mount" and "tools/sysctlfx"
SUBDIRS := $(filter-out $(foreach dir,$(SUBDIRS),$(dir)/%),$(SUBDIRS))


.PHONY: clean force

all: build

# Builds all the components for Cilium by executing make in the respective sub directories.
build: $(SUBDIRS)

# Execute default make target(make all) for the provided subdirectory.
$(SUBDIRS): force
	@ $(MAKE) -C $@ all

# Perform overall cleanup
clean:
	-$(QUIET) for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done

force :;
