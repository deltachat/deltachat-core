# this script generates the c-api html-help-pages
# from the c-core-source using `doxygen`

UPLOADDIR="../../api"

doxygen


# HACK: we use the doxygen commands @defgroup and @addtogroup to sort #define's,
# however,  doxygen files them under the menu entry "Modules".
# with the following lines, we correct the menu entry title.
# if anyone sees a more elegant solution for this, please change it :)
replace_in_html() {
	for currfile in *.js; do
		sed -i "s/$1/$2/g" $currfile
	done
	for currfile in *.html; do
		sed -i "s/$1/$2/g" $currfile
	done
}
cd html
replace_in_html "Modules" "Constants"
replace_in_html "all modules" "all constants"
cd ..


mkdir -p ${UPLOADDIR}/docs/
cp -r html/* ${UPLOADDIR}/docs/
read -p "if not errors are printed above, press ENTER to commit and push the changes"

pushd . > /dev/null

cd ${UPLOADDIR}
git add docs/
git commit -am "update docs"
git push

popd > /dev/null


