#/bin/bash

OUTPUT=$(.env/bin/rst2html5 README.rst 2>&1 >/dev/null)
if [ -n "$OUTPUT" ]; then
    echo -e "README.rst format is incorrect!!!!!\n"
    echo -e "Errors: \n$OUTPUT"
    exit 1
fi
