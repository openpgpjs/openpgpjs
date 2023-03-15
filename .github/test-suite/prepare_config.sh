CONFIG_TEMPLATE=$1
CONFIG_OUTPUT=$2
OPENPGPJS_BRANCH=$3
OPENPGPJS_MAIN=$4
cat $CONFIG_TEMPLATE \
    | sed "s@__OPENPGPJS_BRANCH__@${OPENPGPJS_BRANCH}@g" \
    | sed "s@__OPENPGPJS_MAIN__@${OPENPGPJS_MAIN}@g" \
    | sed "s@__SQOP__@${SQOP}@g" \
    | sed "s@__GPGME_SOP__@${GPGME_SOP}@g" \
    | sed "s@__GOSOP__@${GOSOP}@g" \
    | sed "s@__SOP_OPENPGPJS__@${SOP_OPENPGPJS}@g" \
    | sed "s@__RNP_SOP__@${RNP_SOP}@g" \
    > $CONFIG_OUTPUT