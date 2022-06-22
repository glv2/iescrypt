// Generated with hard coded official vectors, and
// random vectors with libsodium and ed25519-donna.
// Download Monocypher's git repository to regenerate.
#include <inttypes.h>
#include <stddef.h>

static const char *chacha20_vectors[]={
  "e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a20748",
  "b3753cff3a6d9901",
  "",
  "e4b5efc932fb5798",
  "",
  "b181071f299aa254a4606ab6a058e0c6fb5598218db71deb473f7d04c152e7e8",
  "57736715dc7b788a",
  "ca",
  "f6f5808bdc50fb80",
  "c1",
  "9f40d6c8348c353b00172655236cddcd1879ca1f04b35f91adab70b81f504035",
  "fc169964a5ae985e",
  "6c11b0b7bb18a51fd77fbffd722aa220efdd8947ca5a5c7fb1c2ebdb9ad1f603801ff22e80314f716af9c22022fa159dbb4b4d3153f999b20ab4769eb1d01c",
  "593e47059549b141",
  "907aae5d8cea5ca4cc0842dd58a333bcffcd8f2a234ab46a7dc78c3d690a3f01f89aa75426cec8469f36e2b4c41fdba7290a18cef9b39f807a20f1b6933807",
  "80bd73e9ca43cdd4eb7173476862df6d2458d6c74739a0ad2169b9c89edd74e1",
  "6fbcecc748c25dc3",
  "38041fc34af0f1bda20eaf3fff7b372aa801eb98a1298bc61028073750831c8cb43cd6822bf3f6fae0801cb6c843d8066b07346635365fb7d6ee54e5c9cd6f05",
  "29958874e0842c12",
  "c44c93948a3ccc5d473d1319efb42d1944e734fc5b613953845be858c5df073e6448a6e442378d631e9705e0efe3e8d7309458542a715453174f21b4ca3562e9",
  "df1a2d6a963a79c58401770a383248b5d70bb4adedcbe520fed634f513b8c2ea",
  "6ab37fe633ba7302",
  "a5db6c2aa209e24478fa1bd6f6ffabe98555e034342cbec07364c54d1e407e282ef08edbfdbde936c9d42df58ae15889f5c939a3087eaeac1f2a58e2c2763d01b5",
  "69239a9ce179621b",
  "fd09781721c44cadcc4286a6c06f1831934c371e56f66f7e30f28425c65c28b7673bfd8a3f924c4db345b15b385e05b1d8262935f73b26bffa8c327be97fae7749",
  "ddf049c971cd99f694e3b2a5e25fa37aedf01bf32e7c679a3187e22a635d301c",
  "e98ad000ca301049",
  "f2e891e403250c3358fc2030b227bb96e93b88f419afe9f9d660e013761228051ec5a8f0c093b33fc60e2cd7a9c845434e95d4319d79d1bdaa8f73853fbd9958e9ffc23a0ecbb7b48dbba63672d582bb83d92249800324cbc9a6e5b37d36887e7c79093f58ef8f1a001585321bfee1714260dd6130cc768d20b14d3850f0ee",
  "7e3639fb14f22b46",
  "2bb10ad9f818fa3928d24eff4b44db7fbad65b78d0c9022c0748cff53ddc9dbf158987739cb3779ebe1b877febcd8ba25f0e0dc5afbde8a550c30059ef72bf9ca8ec166bcf015d95e6a327da53ea626d71e7b8ff61f1780ef4ba9a8e7fd6e92c762834ba57cc8bdd952a8fbb99f415ce4999fce4d5a314d62288544048edcc",
  "f349110e751c16cdb5ed05516df17479937d942c90eb1fb1813062bd3f3f6b76",
  "68cd8fd3afce0cc7",
  "529b87dfc58eceb951e1e53d9e94793329199c42d004bc0f0dab3adf0cd702e99efa5ef6e59d3b201680f8e2d5a4ef7f23f1b6a8e102670a3829a995ae23fbc3a5639e028cd2b5f71bb90c7a1e4a8a05017d26e3afc3a88541f6c3f45d71f8a3cc31a063ea4aad1b4d00db6f5228e9b9b1561a7f61812b8b79e6af4292580d02",
  "f8f7da8f9106fe6a",
  "95548a60e1774d3814da2f4e6d05f71463396f3b02dcfe4f47ce9ec0d88485396ea51ef6164758dbfef8425bd303a5328f79cdc5cdcc27a533134bde8bbd5b67d54af624827cab5454128e3000bb655e2f402b5fed18cad64a679e0966a9a14bb69312b0e6cd922c90778629163e9635a3610986ce9eea32d613a1674e438f0d",
  "ea4f6266d04244303304510272e383eaa51a8ea7099a74bafa3375b210653a0d",
  "2f40b15afd725cf5",
  "065066be1cb803dc158865ed8d7cca72dcf2b7c6b5d0d045bf32b063d3da484ba1843e071b61c49ce7f30ba18a4f7ef2730ecd785494839966f593168e17311913753c59593fc66cb664c1572251132fc28bf37fd8e96f2327cf7948a1126fd37175a91f483d6b3ad92308df7e6daa8bf3efde75f80ad72a49ae0794009e21ad",
  "ffffffffffffffff",
  "9e3d7360a50fffcae4e9ec400fe957a4fb41bf1751bcdf55ddd09355cdd4bf1c0d01dfc30f33f84bfc067b7b5509e5c7edc4c44493e6b83d92cbb868193f7c6a1b919c1b7bf15e8365e9d254da9a73471b956bb1f4e18ac40ab7b732b33a5a20ee113146e6c8a1cc9380ca4b53d17fa0f73a4d09d13aa47bbf57a3ae1e8472cc",
};
static size_t nb_chacha20_vectors=40;
static const char *hchacha20_vectors[]={
  "e4e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a207",
  "48b3753cff3a6d990163e6b60da1e4e5",
  "d805447c583fd97a07a2b7ab66be621ad0fa32d63d86ac20588da90b87c1907b",
};
static size_t nb_hchacha20_vectors=3;
static const char *xchacha20_vectors[]={
  "e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a20748",
  "b3753cff3a6d990163e6b60da1e4e5d6a2df78c16c96a52d",
  "",
  "e4b5efc932fb5798",
  "",
  "fb5598218db71deb473f7d04c152e7e857736715dc7b788aca39a3c96a878019",
  "e8999c815c5723dbfbde05e6c71f118afc0dedb5b9f8dea3",
  "98",
  "c6f8a1251f9ad994",
  "ce",
  "fc169964a5ae985e6c11b0b7bb18a51fd77fbffd722aa220efdd8947ca5a5c7f",
  "b1c2ebdb9ad1f603801ff22e80314f716af9c22022fa159d",
  "bb4b4d3153f999b20ab4769eb1d01c057c5295ed042b4536561dce32478b113adb5b605cac75bcfcacb5e3e811b78e72e398fdd118bf04c6a7ed0756a3533e",
  "35641c67031a10fe",
  "dfd9414fa3546744b8fb2b4f7c83d8fcdb452b7f07704916e17bac8b7696c54ccfa3401a6bfcbebacffd1559db8150ceb7ea2a963ac1f434b498b1a79d2fc2",
  "a20eaf3fff7b372aa801eb98a1298bc61028073750831c8cb43cd6822bf3f6fa",
  "e0801cb6c843d8066b07346635365fb7d6ee54e5c9cd6f05",
  "d76b2bd4caec8d80b58235cb4268543ab0eb865a948cc5b5f6e31f05f8146bd9495acc459d6d200005ee72c3bc3e4ae3badfd79adfe46b2ae1045f78382e04c9",
  "bde0e2149cc1f90e",
  "f90ab4866767e8686ae1cddd6a607dd8c733522163c4584af07db2e0211d2f81eb4a52b87acfa895188d10ec16c9d21a0b7f20a82342e15a0f23de0d773a8f1f",
  "7364c54d1e407e282ef08edbfdbde936c9d42df58ae15889f5c939a3087eaeac",
  "1f2a58e2c2763d01b55744c4a65f4db93adff0078c63f090",
  "fb607a90c87defd622e5f55977877cec9ed88312b0411228540cd6dde6e84cd2da59b1871db119e3298e3c12fe8200a47eddf049c971cd99f694e3b2a5e25fa37a",
  "c0a356c9d7da2928",
  "1fa0dc38852769722f14441e859df73a36ae6f6b256c425216a513e8a79b665e8204b68f8b5b382f0e75691fbdfa6a10e907f30ae0b1f22c9414cc8bd1e4ec926b",
  "c60e2cd7a9c845434e95d4319d79d1bdaa8f73853fbd9958e9ffc23a0ecbb7b4",
  "8dbba63672d582bb83d92249800324cbc9a6e5b37d36887e",
  "7c79093f58ef8f1a001585321bfee1714260dd6130cc768d20b14d3850f0eec0f8f349110e751c16cdb5ed05516df17479937d942c90eb1fb1813062bd3f3f6b7668cd8fd3afce0cc7529b87dfc58eceb951e1e53d9e94793329199c42d004bc0f0dab3adf0cd702e99efa5ef6e59d3b201680f8e2d5a4ef7f23f1b6a8e102",
  "3f21afec4e3df4a4",
  "524ebd3d892718d9555adc88e62237fa93ec714653e2d0cb84a88a46a0f6865240e9123983b8cfa41eb0c2b9aa4ee27a5e602336a9b1d54a52c31b25dade057f3321110ff8ede0c19cf7bfadabef7a5a7ada92bf56eeaee9e93c888776776520bd31ceb14516c6dc4e25d17c46782521d623abce87d6b9d988c540ffd5668d",
  "3829a995ae23fbc3a5639e028cd2b5f71bb90c7a1e4a8a05017d26e3afc3a885",
  "41f6c3f45d71f8a3cc31a063ea4aad1b4d00db6f5228e9b9",
  "b1561a7f61812b8b79e6af4292580d02ea4f6266d04244303304510272e383eaa51a8ea7099a74bafa3375b210653a0d2f40b15afd725cf5065066be1cb803dc158865ed8d7cca72dcf2b7c6b5d0d045bf32b063d3da484ba1843e071b61c49ce7f30ba18a4f7ef2730ecd785494839966f593168e17311913753c59593fc66c",
  "0afe555385d4d096",
  "5a5cf61ddefcff1426cfc248bd07216e213c6cbeb856764392a54beacd598af988fddaf75a609627199ff7844e6ed02d7dbd9b9291e0b80766fd26081051a32acfe495d7b5591a6877711f32f32504aa09d083f000dd3af4ade4c220232f2a27e34c0ec37fe6a23a0907c21c5bae0d8e665d958a33c97e3cd14ebe1628780afb",
  "b664c1572251132fc28bf37fd8e96f2327cf7948a1126fd37175a91f483d6b3a",
  "d92308df7e6daa8bf3efde75f80ad72a49ae0794009e21ad",
  "33fa4141fe5fa79fed12f6a20f51614dc130f45598e92549b113ed6185724507e7fa5a7e8a75b2c7a3ad700919f36a46ea0ffa680857e30188f8a03c7c4b6c11bc39aececec26687233682d31887277028e2fd286f2654c681efd9e7ed6b340874e897337d4dcc672811a6cf4b69086e0a57c266424dc1d10ecbaf0c822cce9e",
  "ffffffffffffffff",
  "a083f3ceb75dc72484a0c11be30aaf42f1a0b009c9ada2da6e70fbd976e246783cd3124a46abfdc15c526ec66f2bd56dc585e419388e246ebe42dd93727f32cd463b6613563bc4aacbc55c4715ca9a8327310bdc06ed6f93e0e10d96a2f52a41af8d371f3f5bb5530ebf4ed47b9eab99d188b00db9b904c17c3a4cb67eed39c8",
};
static size_t nb_xchacha20_vectors=40;
static const char *ietf_chacha20_vectors[]={
  "e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a20748",
  "b3753cff3a6d990163e6b60d",
  "",
  "e4b5efc900000000",
  "",
  "299aa254a4606ab6a058e0c6fb5598218db71deb473f7d04c152e7e857736715",
  "dc7b788aca39a3c96a878019",
  "e8",
  "1ff716fb00000000",
  "6d",
  "00172655236cddcd1879ca1f04b35f91adab70b81f504035fc169964a5ae985e",
  "6c11b0b7bb18a51fd77fbffd",
  "722aa220efdd8947ca5a5c7fb1c2ebdb9ad1f603801ff22e80314f716af9c22022fa159dbb4b4d3153f999b20ab4769eb1d01c057c5295ed042b4536561dce",
  "3b6ce3b400000000",
  "73d5bf251bb890245618a856cb3af96b306aa9febdca3718b4e1ae73a2131ebec185c7c130ffb0f071effed10dfe02e6662b78717580588ac79184e2809743",
  "6862df6d2458d6c74739a0ad2169b9c89edd74e16fbcecc748c25dc338041fc3",
  "4af0f1bda20eaf3fff7b372a",
  "a801eb98a1298bc61028073750831c8cb43cd6822bf3f6fae0801cb6c843d8066b07346635365fb7d6ee54e5c9cd6f05d76b2bd4caec8d80b58235cb4268543a",
  "47fc612f00000000",
  "0924676a2306556857bc3a0ca6b9f2444acc66a89a0135538bd1fc61f09c7d11a973e75b6a76162f9a5a592b40094953594c659eab3ec361217879039d8f8ed0",
  "d70bb4adedcbe520fed634f513b8c2ea6ab37fe633ba7302a5db6c2aa209e244",
  "78fa1bd6f6ffabe98555e034",
  "342cbec07364c54d1e407e282ef08edbfdbde936c9d42df58ae15889f5c939a3087eaeac1f2a58e2c2763d01b55744c4a65f4db93adff0078c63f090fb607a90c8",
  "b5be810500000000",
  "204f9f415e1fab31f4b743d4b21f0089828eea2709dd31ca4a5071bbfd9820a64e1cda8ab1bfcb1f850064ae630d5225e2cf7e74935b19e9710f6ebc484bde29c2",
  "2e7c679a3187e22a635d301ce98ad000ca301049f2e891e403250c3358fc2030",
  "b227bb96e93b88f419afe9f9",
  "d660e013761228051ec5a8f0c093b33fc60e2cd7a9c845434e95d4319d79d1bdaa8f73853fbd9958e9ffc23a0ecbb7b48dbba63672d582bb83d92249800324cbc9a6e5b37d36887e7c79093f58ef8f1a001585321bfee1714260dd6130cc768d20b14d3850f0eec0f8f349110e751c16cdb5ed05516df17479937d942c90eb",
  "f3eb9eb500000000",
  "fc5cce90cf9e250d87703d4fee5b2089821b7d2c5c1620c0a157090831735e156a42a5c97c2d3a2a939f85eea8d013c859bd21827be0db1393e5f977f8f261c413934c84e7d2e9297958bf608a8b82825690bd25bb6d6938c3c60a0cf541191a03f9c8e78151fccd55ed0b73f30dda9561fae06eac7c4e286950e609633282",
  "813062bd3f3f6b7668cd8fd3afce0cc7529b87dfc58eceb951e1e53d9e947933",
  "29199c42d004bc0f0dab3adf",
  "0cd702e99efa5ef6e59d3b201680f8e2d5a4ef7f23f1b6a8e102670a3829a995ae23fbc3a5639e028cd2b5f71bb90c7a1e4a8a05017d26e3afc3a88541f6c3f45d71f8a3cc31a063ea4aad1b4d00db6f5228e9b9b1561a7f61812b8b79e6af4292580d02ea4f6266d04244303304510272e383eaa51a8ea7099a74bafa3375b2",
  "b105c7d100000000",
  "83824a7cc37786be9e636041aa7bb26f3dfe8ac826f43be45d7af3295093eea6a9bad5a097ba87d1604efb35e400234ddebc6d5a9c54e2de8d070d399602d5dfce8c74d1a2902d48ee4b9e430f2a12ed03290f8176e39f4dda73c71bdc03bf0c91d5d59f45fb3cd841adea8371820cc1c097b3291777ff0b5f6e7b60dfad863f",
};
static size_t nb_ietf_chacha20_vectors=35;
static const char *aead_ietf_vectors[]={
  "e4e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a207",
  "48b3753cff3a6d990163e6b60da1e4e5d6a2df78c16c96a5",
  "",
  "",
  "b5ed4c7e63a144f105dbe2b039c7e805",
  "8019e8999c815c5723dbfbde05e6c71f118afc0dedb5b9f8dea398b2d764bca6",
  "8dfc023a9821939d389e38a072cf1b413bb1517c3fe83abe",
  "",
  "86",
  "374190382975907a68e8a341faa0772aa0",
  "f999b20ab4769eb1d01c057c5295ed042b4536561dce32478b113adb5b605cac",
  "75bcfcacb5e3e811b78e72e398fdd118bf04c6a7ed0756a3",
  "",
  "6862df6d2458d6c74739a0ad2169b9c89edd74e16fbcecc748c25dc338041fc34af0f1bda20eaf3fff7b372aa801eb98a1298bc61028073750831c8cb43cd6",
  "9ef6887763d27d843103a44f9b2427e70769050e09c5a6453280159a6eef522bf4540e3d559aeaace7b339c98520921d380faf3c64b2593792b2a7d53d42ed738df4a729d618649a190338bc41e4a5",
  "9d6d200005ee72c3bc3e4ae3badfd79adfe46b2ae1045f78382e04c969df1a2d",
  "6a963a79c58401770a383248b5d70bb4adedcbe520fed634",
  "",
  "34342cbec07364c54d1e407e282ef08edbfdbde936c9d42df58ae15889f5c939a3087eaeac1f2a58e2c2763d01b55744c4a65f4db93adff0078c63f090fb607a",
  "01c2a664d680021a34b1353258d2a8d16773c68db39d8c0de0dce962a5f0ddc13f78a1a6fa74cf500e78820c19252c4a2a1ecf987de69651a31bb390f3319ad658e136a56e0a0140cef60e9af8ad7392",
  "1bf32e7c679a3187e22a635d301ce98ad000ca301049f2e891e403250c3358fc",
  "2030b227bb96e93b88f419afe9f9d660e013761228051ec5",
  "",
  "c23a0ecbb7b48dbba63672d582bb83d92249800324cbc9a6e5b37d36887e7c79093f58ef8f1a001585321bfee1714260dd6130cc768d20b14d3850f0eec0f8f349",
  "d00030016722e4e1c20592a0f643bbe63cfa22b937430eaca5058f19cc86f45269785e8a6fb2247b1beb510ac1b3b5d8ddf42eb175c95c9d0d9603189f8f41c850c875a2f9ab9451f418f1c102e64d5fe0",
  "ab3adf0cd702e99efa5ef6e59d3b201680f8e2d5a4ef7f23f1b6a8e102670a38",
  "29a995ae23fbc3a5639e028cd2b5f71bb90c7a1e4a8a0501",
  "",
  "561a7f61812b8b79e6af4292580d02ea4f6266d04244303304510272e383eaa51a8ea7099a74bafa3375b210653a0d2f40b15afd725cf5065066be1cb803dc158865ed8d7cca72dcf2b7c6b5d0d045bf32b063d3da484ba1843e071b61c49ce7f30ba18a4f7ef2730ecd785494839966f593168e17311913753c59593fc66c",
  "4c56ae846df2a22857d81f76a6dd614c09ca92cbfbbe7423e4a6a1fe4dd6faa31bbce300be08b2ffe49f186214675e36a25d57c74611534dee35b301ee5e00657911b161a3060bea0871cc726db66d11e1dbbd5def385dc0c953914ca8eac6129563ac4bc47e39e65d8d276eb0b099576b542f2ff787c27789e565c4fbe46da193c11495f10a08f64fb026b482da54",
  "64c1572251132fc28bf37fd8e96f2327cf7948a1126fd37175a91f483d6b3ad9",
  "2308df7e6daa8bf3efde75f80ad72a49ae0794009e21ad33",
  "",
  "fa5a7e8a75b2c7a3ad700919f36a46ea0ffa680857e30188f8a03c7c4b6c11bc39aececec26687233682d31887277028e2fd286f2654c681efd9e7ed6b340874e897337d4dcc672811a6cf4b69086e0a57c266424dc1d10ecbaf0c822cce9e4f17b19e0ece39c180a4c756c03c19900280ff6cdebe5174d507c6e0860c38c353",
  "e16c5303bff1085eae99ecfcca64e07ec76709b336598c9c4276a88e2ac3106630ec7b0f4fa2b455fd448945fe65798da3c8715df79b27f94dafd5a27ca47b6672149962cf8b8f019c4a93c71902dd3b2b8d9cc4bf2ff30d50f18480120bc638c6fa7397691aae3898bdf0a0f3dcbd749d03b8429cc1eb624c67d1acbce58a32a8adcb5bd809bbbb960f3fa8bf380e9f",
  "7176c58965b74a56c52b3151bb8a149cf4f82158d57c823f3a90c6b427912226",
  "ff604d9abee1fb8c8d35530a0cd5808e53e308ac580f7318",
  "",
  "6477fbb05c7c35956c3c0c5f342355fa",
  "cb399b45596ac537bdb1cae9d439e26ba530343ebb3bebb73a238af37efe26fc",
  "543894006b73f3d70fc04b15d0c2a5dfa650be5044fb5061811b866be7f9d623",
  "fcb077ee19421610aeb263c57faef00662d424c07a7aa500",
  "50",
  "ab2911b42074414e387d7247fa505548",
  "edeb2fdf5d7d9bf5d638973886aaf2b1ee4fc2a15ebc04c8a6339b1c3344ece0",
  "62d3d607d6bf63c6760b802483b0e3aaa9dd4f79c6c5e93e6b51da45018c6bde",
  "108f81f9abfa23640b83cfe3fed34bcf6640bf0baf647daf",
  "e9bc99acee972b5a152efa3e69e50f",
  "3786aca4c6b7e224163ea928771fde37",
  "bbab31c2ba755007513a20995cc9d43998f7d9395a83284ddf4348ecb4830859",
  "c2f8b252a18a29c44dbfbb62cbe6c3dfd4db55378734d8110b8f20f1d1ada6dd",
  "d4da48fb09c06580eb46bbc5ca62bfab40b184271b73b710",
  "d40cb63435042c9b526d1e5c3a77bfc5",
  "11dd1e876f527d81ec81df06c7e426b7",
  "c5023859611cf67a39bffa690d2f839429b23f99a17ec58e5d43b3e1eefc35c3",
  "820032e031949f1e97e8ad5eb5a75cc805900850969de48e74267873d65e0d67",
  "482d1c6f9a22450bff02814b8626a89534495c3bc3c8897a",
  "096fbc2f9e50fda78ee3c8b0fb60231ae5",
  "01ee35b10ac1efa06855ef67ece02508",
  "0e9772515b51f4e6fa8195611dfafa65146bc05c66f1e8e0be1f1678a1e101d9",
  "9849fcae816135f8ff7c83156a36aebdd8b11b679e1325659890870da65bd4c7",
  "90ceb7351cdf29dbda3e68c2d64c04c7da7340fd622e6be1",
  "4bd10d4003b8cf7e956bc847cfb0dea015d884f5761e9dfb9b2cfc2a8b4032",
  "2aa92e5bd6515817db7d15af98806caa",
  "17c4b7fa1f5bf1e69e882d760b303c74590a31d338c87d608786cc6443c8d32a",
  "b118784e65a1f1d1964af9a24f53e3bcfe779241591e2c385be3b579780c5cc0",
  "c490bc2ed9f06e129c52d57da020389a30134a40ddbf13e7",
  "16a1f84335380b528cd7b6d29fbb5d7f97699f3c6d9284e1ef22fa05ad1f6ab7",
  "99f2ed1a1d0611de572c0e8623d674bd",
  "77b0a34ca0404238bdbe8e82a0b52a3cb62d441b580a49e81027fed18514c7d5",
};
static size_t nb_aead_ietf_vectors=70;
static const char *poly1305_vectors[]={
  "e4e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a207",
  "",
  "227e68e4c1e68ce67ee88e6be251a207",
  "81ac001b08d6577bd91ce991c4c45c46bc84d5465fc9139bf17042ae7313181f",
  "7a",
  "403bd4853fd1c55af2077780de9c1284",
  "4a70a7e992b43e0b18578e892e954c40a51abdb5a85d300c32f391c45d6ef4db",
  "043ddcf4214f24ea6ef6b181071f29",
  "ff3de42a679eb874a5d4525abf3078fc",
  "1deb473f7d04c152e7e857736715dc7b788aca39a3c96a878019e8999c815c57",
  "23dbfbde05e6c71f118afc0dedb5b9f8",
  "1d07a51dfe091076038f397099d15eb0",
  "389e38a072cf1b413bb1517c3fe83abebb1cdf3a218abb1b0c01da64c24f59ee",
  "d19cfb8cb3940aba546f0be57895e2cc86",
  "320f841c889560a5dbee77df34ecd50e",
  "e5d73f1c8c5376c1220ff3d9d53eeb65cc53599f40d6c8348c353b0017265523",
  "6cddcd1879ca1f04b35f91adab70b81f504035fc169964a5ae985e6c11b0b7",
  "32cefab76877cdd41a99c813d0a1ab15",
  "18a51fd77fbffd722aa220efdd8947ca5a5c7fb1c2ebdb9ad1f603801ff22e80",
  "314f716af9c22022fa159dbb4b4d3153f999b20ab4769eb1d01c057c5295ed04",
  "6909e2774445104a4a0bc810da0ceb0d",
};
static size_t nb_poly1305_vectors=21;
static const char *blake2b_vectors[]={
  "",
  "",
  "cae66941d9efbd404e4d88758ea67670",
  "e5",
  "",
  "2a294c4a9c276126c47e584eaf7e3396",
  "f8146bd9495acc459d6d200005ee72c3bc3e4ae3badfd79adfe46b2ae1045f78382e04c969df1a2d6a963a79c58401770a383248b5d70bb4adedcbe520fed634f513b8c2ea6ab37fe633ba7302a5db6c2aa209e24478fa1bd6f6ffabe98555e034342cbec07364c54d1e407e282ef08edbfdbde936c9d42df58ae15889f5c9",
  "",
  "b28674d2dfede11f76e50f0e3081d74c",
  "a63672d582bb83d92249800324cbc9a6e5b37d36887e7c79093f58ef8f1a001585321bfee1714260dd6130cc768d20b14d3850f0eec0f8f349110e751c16cdb5ed05516df17479937d942c90eb1fb1813062bd3f3f6b7668cd8fd3afce0cc7529b87dfc58eceb951e1e53d9e94793329199c42d004bc0f0dab3adf0cd702e99e",
  "",
  "663115a7fe0e0085cadf1818fa03421d",
  "f593168e17311913753c59593fc66cb664c1572251132fc28bf37fd8e96f2327cf7948a1126fd37175a91f483d6b3ad92308df7e6daa8bf3efde75f80ad72a49ae0794009e21ad33fa4141fe5fa79fed12f6a20f51614dc130f45598e92549b113ed6185724507e7fa5a7e8a75b2c7a3ad700919f36a46ea0ffa680857e30188f8",
  "",
  "ff0a0433af77b0676a43e1e69b9294d7",
  "6477fbb05c7c35956c3c0c5f342355fa0850307998642501c025e3873ebac3ccd749d8379ae6d830f785ec104897bd723d34ad20c9d36bfe371df46aebc6d4595d490a770bee4dd0be6a5a0b5e95645c7dcbc03c27010df3320fe75b0a3ecc8983ad94217e80348fd0f3f54e54b95bb548dc2225a264443732b41b861590358d543894006b73f3d70fc04b15d0c2a5dfa650be5044fb5061811b866be7f9d623fcb077ee19421610aeb263c57faef00662d424c07a7aa5005068b262251c0667a4e2e4b12f5df7f509564517887e370b425fabab1ce9e733ab2911b42074414e387d7247fa5055489bbd4b7d4de256de723566c1c2d3ecee8c10e7d98233db",
  "",
  "fa15fe1df94964869810a57fa2c9f82f",
  "7c12457eb5614f87f1fdc40118906d02c602059d48ae05ae62d3d607d6bf63c6760b802483b0e3aaa9dd4f79c6c5e93e6b51da45018c6bde108f81f9abfa23640b83cfe3fed34bcf6640bf0baf647dafe9bc99acee972b5a152efa3e69e50f343bc12887fec8e70db73b4b48dce564d83786aca4c6b7e224163ea928771fde3778c453b35d98deced812fc5685843565b73d097601d3558278bd9d7327de5fdaa2b842050b370e837ef811a496169d5ff768878766c08c45561fdc2aad6469c11380c3d3f873c7233c541ea4c43824ecd8bf7e11ac8486208fb685218d46736e51103d1fae0e8e368f25480ee7328381c2f8b252a18a29c44dbfbb62cbe6c3df",
  "",
  "50089bdcf51629a715eb1b3345a0c2fc",
  "b3451318590c84e311dd1e876f527d81",
  "",
  "13e40814a705dac02c3a1de24eb9e6cf",
  "8a52102e2903352b5ec66cbed7474a91",
  "96",
  "ef0733ef5b4381bad3b00a6269bbc282",
  "97699f3c6d9284e1ef22fa05ad1f6ab7",
  "0d200c182251f5a9cafbc17c4bdacb3411651e4088dec905251ae93c899860061d340da02e519a254e109592caae83d46aad5dd4338e034f0660693ea9e691",
  "6318f617c6c8788bcedb7177635a449e",
  "5cd890b165ef0445d3b75055261be279",
  "5c9fc34bf3b7633130b5341dc0560406d0f4ab5110a8ab1417e4127d459157b58b20256edf901d5a8bc0f71f6898a6b1d0818edb2f561d3219752a709abaa318",
  "264f2e37d05f658f60d69b312abb90e8",
  "b5f0c69568656661fbcd3bca40b22c65",
  "",
  "",
  "aeb71797e433c16ed303017030b2d85b",
  "",
  "01",
  "7c72d9947280f5c974ff04857caecab0",
  "",
  "2bfb488870d7a53f5bb5f3bc72b1433ae7908408d237fb4601141e3f07e0e445a8725bd48c0d4f1ba8a7c4923258d6ef90d598af6020a1a3e5eddb5c51cfbd",
  "48fbca32ec758a3b09ebd2a19e6d91ae",
  "",
  "6111d2b0526416d0aac7112a7003391899c7eae8615d2778f3d053d6eab255bbcc2186267a67b540e5825f6d5d950c2f36d5588b45b6a113908ad73f6da77ff8",
};
static size_t nb_blake2b_vectors=45;
static const char *sha512_vectors[]={
  "",
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  "38",
  "bc23b8b01772d2dd67efb8fe1a5e6bd0f44b97c36101be6cc09f253b53e68d67a22e4643068dfd1341980134ea57570acf65e306e4d96cef4d560384894c88a4",
  "ca43cdd4eb7173476862df6d2458d6c74739a0ad2169b9c89edd74e16fbcecc748c25dc338041fc34af0f1bda20eaf3fff7b372aa801eb98a1298bc61028073750831c8cb43cd6822bf3f6fae0801cb6c843d8066b07346635365fb7d6ee54e5c9cd6f05d76b2bd4caec8d80b58235cb4268543ab0eb865a948cc5b5f6e31f",
  "0c7ea31f5fa48e7c869feea1ae0069f7327d1189019576688f76a222558ed18fc18e420655adac27f7e1659a8b196b30a6c705a99878219f90da7f2ecc6a8c0f",
  "a3087eaeac1f2a58e2c2763d01b55744c4a65f4db93adff0078c63f090fb607a90c87defd622e5f55977877cec9ed88312b0411228540cd6dde6e84cd2da59b1871db119e3298e3c12fe8200a47eddf049c971cd99f694e3b2a5e25fa37aedf01bf32e7c679a3187e22a635d301ce98ad000ca301049f2e891e403250c3358fc",
  "39b3208cddc3275ec7857fb8fc9e48540977ea6c0665248f7164f87b5a640ef300d7bb21d82db9b5b585b5ce82dcbcb7ae4d6883a6bd6e3175b9a6249c8a6d88",
  "ed05516df17479937d942c90eb1fb1813062bd3f3f6b7668cd8fd3afce0cc7529b87dfc58eceb951e1e53d9e94793329199c42d004bc0f0dab3adf0cd702e99efa5ef6e59d3b201680f8e2d5a4ef7f23f1b6a8e102670a3829a995ae23fbc3a5639e028cd2b5f71bb90c7a1e4a8a05017d26e3afc3a88541f6c3f45d71f8a3cc31",
  "8df0329b3dcb8510808919ddf8064b96bb641cad8160a22e7abfdad9433a86c62edbd2b6a46ee18c5e0391c06c51d96e3240028c7c4aa2c25dc77c1b72a2e0ed",
  "f593168e17311913753c59593fc66cb664c1572251132fc28bf37fd8e96f2327cf7948a1126fd37175a91f483d6b3ad92308df7e6daa8bf3efde75f80ad72a49ae0794009e21ad33fa4141fe5fa79fed12f6a20f51614dc130f45598e92549b113ed6185724507e7fa5a7e8a75b2c7a3ad700919f36a46ea0ffa680857e30188f8a03c7c4b6c11bc39aececec26687233682d31887277028e2fd286f2654c681efd9e7ed6b340874e897337d4dcc672811a6cf4b69086e0a57c266424dc1d10ecbaf0c822cce9e4f17b19e0ece39c180a4c756c03c19900280ff6cdebe5174d507c6e0860c38c3537176c58965b74a56c52b3151bb8a149cf4f82158d57c82",
  "1afec592c116573a7acea54c46ad42c5e589a546d0afbe7dcabaacaedf163c3f9432b525be87813744b88c9b7b7f640735ff6de8f5e968e2c8de289785fa1641",
  "3a90c6b427912226ff604d9abee1fb8c8d35530a0cd5808e53e308ac580f7318fe2ab2a4933b5d90db718aa3440fbe9ba17f09716219bdffc93a189e410a6a3e6477fbb05c7c35956c3c0c5f342355fa0850307998642501c025e3873ebac3ccd749d8379ae6d830f785ec104897bd723d34ad20c9d36bfe371df46aebc6d4595d490a770bee4dd0be6a5a0b5e95645c7dcbc03c27010df3320fe75b0a3ecc8983ad94217e80348fd0f3f54e54b95bb548dc2225a264443732b41b861590358d543894006b73f3d70fc04b15d0c2a5dfa650be5044fb5061811b866be7f9d623fcb077ee19421610aeb263c57faef00662d424c07a7aa5005068b262251c0667",
  "4bf909661a603c30199c63eefe96ac7b5489b2790c47db8f97b99cbc0fb4701831f7682d34302415974ff3f8e43f2592c6ce2c6e8a5518c3468a4cad6699ec35",
};
static size_t nb_sha512_vectors=14;
static const char *hmac_sha512_vectors[]={
  "",
  "389e38a072cf1b413bb1517c3fe83abe",
  "9689b839211c1751e1faee45edd4662c6102049ba76c3eef46a28cc268818cc54b8955b68dfd17d6f0993844bf9952f6158aa2c3fe780e6a89d975597a504ada",
  "ca",
  "a3087eaeac1f2a58e2c2763d01b55744",
  "3c0119c12ed65c15b5343bcbf0d04a1b22c9957f3aedfb07d1d3dea5158c4f133efddbbff90e17733d5853818c9af7fafec2dd280f0e27855dac473cf30abe0c",
  "ed05516df17479937d942c90eb1fb1813062bd3f3f6b7668cd8fd3afce0cc7529b87dfc58eceb951e1e53d9e94793329199c42d004bc0f0dab3adf0cd702e9",
  "f593168e17311913753c59593fc66cb6",
  "a62e149fef7b91b9c7f327847d81179a4bec216d30bc005d7a4708f84e2cd35ddc3ea8eb51e1bff209d07deaf5e88ae0900c7203db57dd372ada435a5518e2b6",
  "3a90c6b427912226ff604d9abee1fb8c8d35530a0cd5808e53e308ac580f7318fe2ab2a4933b5d90db718aa3440fbe9ba17f09716219bdffc93a189e410a6a3e",
  "a4e2e4b12f5df7f509564517887e370b",
  "276785363a14f38d660d635dfa42ff079af139e9901f91f29240275fbf290a7320e1df5778a9239bade44c90bfe5e3d50d99fdc0570359a472bc931a123a7e19",
  "78c453b35d98deced812fc5685843565b73d097601d3558278bd9d7327de5fdaa2b842050b370e837ef811a496169d5ff768878766c08c45561fdc2aad6469c113",
  "60fa0114802ee333d7c49ccaad8108db",
  "d31bba716cf3bb1d322ce9e4e6cda884845a16db546a90dd5bef2fe7bb836bad8e995f743a978dab6b11ee31b6c8bff2f2d747408bc54c7a75c049e243565470",
  "8a52102e2903352b5ec66cbed7474a91d7ca3f49fdc859b3e1705e1e05b124789849fcae816135f8ff7c83156a36aebdd8b11b679e1325659890870da65bd4c790ceb7351cdf29dbda3e68c2d64c04c7da7340fd622e6be14bd10d4003b8cf7e956bc847cfb0dea015d884f5761e9dfb9b2cfc2a8b40325a2aa92e5bd65158",
  "964af9a24f53e3bcfe779241591e2c38",
  "3cb55d24a444711f3312818fb019b9c29842271896abd68413aaa6d13771c9a9997e332e36bc6cd8882dda982ee8ba1e102a6f01a996bef3bf8ce3393cb02b4d",
  "f9b8e57564807df84a1d2143003c7c31c1ecfb0fa02c0a88f9b13f45f06f30ca463cba3d090f62651ef12368bee0db5fba7b79b95fb51289e4ba9be86c19cb700d200c182251f5a9cafbc17c4bdacb3411651e4088dec905251ae93c899860061d340da02e519a254e109592caae83d46aad5dd4338e034f0660693ea9e6914e",
  "23ca891e5af07c3e5c47a168e79af48f",
  "36e2a5fd3e8b2560e24ba08002469a98c50f56080e4cb18665dc1c7dadd9ec73664298a0d852504f5b3c1633247a41e47744915780d899e3e2afe14b86ab29ed",
  "96fce921032289e9e686d8f207c5b4e7273feadd17d02148810c33e07dc7d92b6b034b4c953b7e0900da7170bbca5c72ebbb007959720860a69357ca495148faa1e5924ab091d3fb4996c3efc3c48b123a08998c55223a940e3fa0bbe1b1f4bf2ec798c3209c6cde322b5b08a73544e078286a8e5b7177019b72dcbe98d2a1280b",
  "aeb71797e433c16ed303017030b2d85b",
  "5c87ad41b5e45e91fce3a756fdb2382916fc2c7d6c00277db52bc4c3d8d1a93ebfd18497af4186e7f2d3c40de52094100681fe58a5fded5510b5dff983e75db6",
  "",
  "",
  "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
  "",
  "dc",
  "cfd55a01855eddd5746c64f58ce5fc5e002cd28632c3224288dbe816ce8fb370b2b355ca7ea0eda2a4f75395db7b94b2b06688811f0d7733122189589f82b437",
  "",
  "481e1604d2e5dfcf0d9943ae21d6efab804755197bff9f24eee982b0f9089288cf7b4570ac320b344f4f70f31f530c2312db5b7241651d361a91f7986db3922aabcd660b88d14c1c1601492321379521c1e4274d661113338c8a5b98d6c12d985f1b73d5b3d7592b2d0ea7be0181ae20d09d6051782c35c8537a597818b5a8",
  "8fe0c5422e148c351107dda1e696bccbfdacd9c4b21a63b0ecb36d45864eaa72963c0be609fa9ca9500171ac785c19e5929c141cd1f6cee605f05bab8809ef66",
  "",
  "a46ff45937e5f0c485c88631147283987321c85d4a447015bdb4c7921a6e927b6c8b7f7e40a17eb87f1874b7c50225d8544a01cc2cf0ed8c30c3dcf2ca6ff3ef75798ff9253562ecba3e7e42a43c6fd74a3c4330ea178daafa0532305e8356f1aa5f91ca91dcda75d7167e1585e0211eb3b78e6be0cf50209ab6747b4a24c053",
  "03017550f2050653118444fc09e828f9d8d7fc6f245bd96ac82d20d4c40b31bb7d3237df3f22d129de5cebd8b91b1a69bb7050373532293bf35f66a06da43a95",
  "",
  "d4aa41c8434e57b47edf32f6cf6ed1bed6c383e898df44d84558837a0178af8b11417eda347fc40c678121bf0067eb4677a84f442fac0f3ada2412a69794c521b769a9e4a3b0c80bba876e96ac0eeb9194cb23669cfe964d087f33f4366d4bdd721907f828f383c11bb6d956d64db4a8eaad21ac20d2c31fc52f08d756be446b99",
  "dd87e1b28bffc10ec0a4bd8e2808f003fdeefa822f25ccabb6a7d4c0381499ce4413de701771ab3172e4777ebdf1999d27dc1941a5c3cc0ac156b7cb67552a27",
  "",
  "f606ac7b059ba616ec1e952227f31cf0a83dcb66613c012cdea2a3776961f0efd398712051b7e7b8500ecbd030d2c6a0012b8eaeeabbcc0d6f1e03f4acf709b3bde30f4e8aa3ebb0e8f75158be727463e25d2b3f02db5cf3342581ce7279c118bb8b0d496b610c2d51967d12821cf86d796b7cd7ad2cbd5c0f165b232f281464e48f0b0d2577542ad3465bf6c063435390470388a27d938b113c74cf1d962c864f2971a0b18808649f978cc94de8b8f70fa5cf3ec0bad1a92499b68660c1fd2f809bb26aee29f93ab4484694506fae71d307ac45239a431f3f51285aba0dbd3afdae0231c4a1fc14b21ba2f1c27548d4c259544e80b94696da838ad6186b2e",
  "800ab7f4817cf9a1a7d7d711ea097709ed18be383e7caaf6da72bc9e486dacb2894a3e20e0759cec7ec0550da76cf613d02e10ec2c4c697648998586d107ce64",
  "",
  "6ab33d45513b7013624e01e15f616a3436caa8813c863a13eb85e06a973f95204b265c9f76496407bdd1bd16b7f6ea3e97f3346e63d5e05f9896b1821e3dbe382a8849e3e27e05c8572140297d86473e720d62e6c7ef1766e4aff8313c688b6b91667b20ccfc055f0d7917eff1c713f3712d948055a3139e6d758a308322503f4f28977329a2153bd6a8c1d47e8877a4abfcef83cdff4daa74845384d8bdcac050bddc4bfa7cdc185d3b2528559936510bfe814ae162eaddf609992f6796654a59a66323292142ca499c44cb95bc308c10d44aa534066efb413fbd7e622fb2a2366b20439156728d7753c598106508878bbf4467d9c7812ea686683580365a50",
  "ffb3011fcde35b8ff8c09a62fe02e7f17aefd1f458f3c01caa2d57b77699dd335f9670d359fc99c72b30ad3e92c9d39000b127967284cca14b759275531eaba2",
};
static size_t nb_hmac_sha512_vectors=45;
static const char *argon2i_vectors[]={
  "0800000000000000",
  "0300000000000000",
  "e4e4c4054fe35a75d9c0f679ad8770d8",
  "227e68e4c1e68ce67ee88e6be251a207",
  "",
  "",
  "2a2ec585be2ec27c215f677e947c212b1b85de797167d4950e29987977c941117c4c5f6f6f547e62d76b88fa121781986a37ea14dc394917af5396ea58915d",
  "0800000000000000",
  "0300000000000000",
  "48b3753cff3a6d990163e6b60da1e4e5",
  "d6a2df78c16c96a52d4fb01ea4ecf70e",
  "",
  "",
  "ec60819d04c1d35416d20abc5908dd972acbfd8f6a282ca2b642064242526683c0f1b237f38bac8279571f049bfed4d8d177ea336f2ec96456eb6c584d3c9607",
};
static size_t nb_argon2i_vectors=14;
static const char *edDSA_vectors[]={
  "50831c8cb43cd6822bf3f6fae0801cb6c843d8066b07346635365fb7d6ee54e5",
  "b600ab324d70d2372f3ba5a0d8bdd8b8e797f780b642bd56e69a18db74c389bc",
  "c9cd6f05d76b2bd4caec8d80b58235cb42",
  "0bfa8d629fe89bd9591f20575144f0445958fd3574179ec4a9b6ee85787c23d69b4f009d3ed3bd2bb62226638602b95bc4719a1d2c60afb07ed95c959628ff0c",
};
static size_t nb_edDSA_vectors=4;
static const char *ed_25519_vectors[]={
  "50831c8cb43cd6822bf3f6fae0801cb6c843d8066b07346635365fb7d6ee54e5",
  "38bfc0b57ba86490aa2f41a3209e360ea4df055f22c07c7f54326d36780f42f6",
  "c9cd6f05d76b2bd4caec8d80b58235cb42",
  "428bda84b67e78d45c5531e194d1caee74b6242417c0237d34132546f7c0e70d8af611ef57248e0437241f5c3592063b5d13b94b78fadc39cf9a703a6920660a",
};
static size_t nb_ed_25519_vectors=4;
static const char *ed_25519_check_vectors[]={
  "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
  "7bdc3f9919a05f1d5db4a3ada896094f6871c1f37afc75db82ec3147d84d6f237b7e5ecc26b59cfea0c7eaf1052dc427b0f724615be9c3d3e01356c65b9b5109",
  "00",
  "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
  "ffffffffffffffffffffffffffffffff",
  "5dbd7360e55aa38e855d6ad48c34bd35b7871628508906861a7c4776765ed7d1e13d910faabd689ec8618b78295c8ab8f0e19c8b4b43eb8685778499e943ae04",
  "00",
  "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
  "3f",
  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "ff",
};
static size_t nb_ed_25519_check_vectors=12;
static const char *x25519_pk_vectors[]={
  "e4e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a207",
  "e5410cf8d4524fe8b010158cf7c541420e996b6b1378d4ed88deaaee29263b12",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
};
static size_t nb_x25519_pk_vectors=4;
static const char *key_exchange_vectors[]={
  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  "8e47ca376bdc7e59d2ced8107ceb2c27f4a80e8575f996baffb1a869ffcd5179",
};
static size_t nb_key_exchange_vectors=3;
static const char *elligator_inv_vectors[]={
  "2920d46f2f37b04d00ff73df4115fda3876810c2144e94a7e6d0c09290ff7359",
  "d5",
  "ff",
  "00",
  "70e7a067416c79ca10ea92e00b0e15cd50569e3298b6358ad6b016826b1a5b2b",
  "dd",
  "ff",
  "00",
  "89bbc72dc9f7f5b863489c606514a39f4e844061ba5c9dec8095fa8c8e657170",
  "2e",
  "ff",
  "00",
  "df1d73ff8919c4795a72077558dde8a99163591bfe015147548708e067f47e28",
  "48",
  "00",
  "7c0e535eb69f95f02c4639e1d9668ce0c78b17d94e09a08756ec8ff266595076",
  "c74d0b2a03a3e2d5138e4eb0378c1b13dc2dfe145b62fbd4bb476014bfcd4034",
  "57",
  "00",
  "b48cfc36901caa3fd2d3997075c716b33165d7e60ed1770007289245d6a70946",
  "3bd31879f188a6111d3633c8b1053138eaf8f11423c779f23288821b58181856",
  "b6",
  "00",
  "19288fbd99b6a33e3374aed8faea2fb3356c2965c11ed9d09043b27f3d8f8796",
  "a23740a8663e73d9b9e8c11fd0991efad5735f9533550b61a058b60acb3ada1f",
  "13",
  "00",
  "34e6d2b0a37d4719a71b918a7095e42f7b2d0a51473704d2a942a10baee08705",
  "3338ab54956d68a9186bdf5b97f03762bdde1551fde608885b035fc854177259",
  "4e",
  "00",
  "43e97d6b5ddcf115d66341d293e627918299a171e04637f32b9b09505a971c64",
  "06a64676b6b162cf03ae11efec6a07a8205638523ca2631519d18ba3a8858568",
  "6b",
  "00",
  "d72d68c2e7f8fff0a946f8120b3004831e1e194369ae20d67cd1e1da3a534b54",
  "77b951a3bf0ad919a950bcd1fdcffd2a659a1ce7d95557a71b9fc4cbd1ab3a65",
  "a4",
  "00",
  "282ae366b62e6d3043735d989dfb7455bab90ba17018827c4df05b14c964d6af",
  "f7d574f5cd7847043acc1f8cd2a4c1325e6a97281c099dac93ddc54fc0c63e0b",
  "23",
  "00",
  "62323f31d49906ef7422aa0a3015491dd463ddbe0b440efeb9574277eab63d39",
  "67e965bac8b9406bb5048c6e30b895e142424a54fcc0c2a21e45fa5a6ff96d45",
  "12",
  "00",
  "92259700a11805a3a74e5fca9979ffb83853bba64d13398c0c8d0e577c3c4117",
  "8199de6f012e0ca8ea05f1767592466cbdcd9c1402a727da4288a8d7075f6e21",
  "05",
  "00",
  "318a4c9b941b54bb679e0ecbcfdf19abe2929143ed39abdad6e672d45edbcf34",
  "5ba0832ca17067095ca32b74a0d134bd09b21b5dce536a4a1f3c41298c97893d",
  "0c",
  "00",
  "1950ba33c7d6f56945fcf47ebaf88e003c34c2f70f080dbf410f8985440f2a0b",
  "32d57bcd24f11916e7b96b7814598b15ea609258b40dde23eb0b64734878cf5f",
  "49",
  "00",
  "c2d517d0bf0e573034ee0d297923b4965f6b75c6bc7888e0c8078e3a9fe92e74",
  "aeb757f254b6dfe33e1df62e2d85c6fac47d5f3535f969de6882fac2bf0a4f19",
  "9e",
  "00",
  "58daf8d2ab3bff7fd1d99e462b5b7bc34d63dafecf43c3bdf925d1f919216392",
  "732f35e5f3fbac1edad39eef1c4633251d4b8a070712a91b1d4ab860ce68c16a",
  "83",
  "00",
  "3f436796492ea02bb04fa7bee3d3c51b254c1003d943c984eb59a580a7e1ea84",
  "9fa8d210f4e00b37444d24567e72d019e32f271954a080371a88875d4911555d",
  "4a",
  "00",
  "515b649d380b9e4e3583025f360bf27331ce267f85f3509c10a0dc429ff39b60",
  "af935c1ac0e61cdcaf16f8b2df6f6eed49805d5025ef6f2ddfe2bb358ab35e35",
  "51",
  "00",
  "0892930b2fa529e56758523552d6cc33fe488f0a2d106124c1ded9c35d6c965b",
};
static size_t nb_elligator_inv_vectors=76;
static const char *elligator_dir_vectors[]={
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000040",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "00000000000000000000000000000000000000000000000000000000000000c0",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "673a505e107189ee54ca93310ac42e4545e9e59050aaac6f8b5f64295c8ec02f",
  "242ae39ef158ed60f20b89396d7d7eef5374aba15dc312a6aea6d1e57cacf85e",
  "922688fa428d42bc1fa8806998fbc5959ae801817e85a42a45e8ec25a0d7545a",
  "696f341266c64bcfa7afa834f8c34b2730be11c932e08474d1a22f26ed82410b",
  "0d3b0eb88b74ed13d5f6a130e03c4ad607817057dc227152827c0506a538bbba",
  "0b00df174d9fb0b6ee584d2cf05613130bad18875268c38b377e86dfefef177f",
  "01a3ea5658f4e00622eeacf724e0bd82068992fae66ed2b04a8599be16662ef5",
  "7ae4c58bc647b5646c9f5ae4c2554ccbf7c6e428e7b242a574a5a9c293c21f7e",
  "69599ab5a829c3e9515128d368da7354a8b69fcee4e34d0a668b783b6cae550f",
  "09024abaaef243e3b69366397e8dfc1fdc14a0ecc7cf497cbe4f328839acce69",
  "9172922f96d2fa41ea0daf961857056f1656ab8406db80eaeae76af58f8c9f50",
  "beab745a2a4b4e7f1a7335c3ffcdbd85139f3a72b667a01ee3e3ae0e530b3372",
  "6850a20ac5b6d2fa7af7042ad5be234d3311b9fb303753dd2b610bd566983281",
  "1287388eb2beeff706edb9cf4fcfdd35757f22541b61528570b86e8915be1530",
  "84417826c0e80af7cb25a73af1ba87594ff7048a26248b5757e52f2824e068f1",
  "51acd2e8910e7d28b4993db7e97e2b995005f26736f60dcdde94bdf8cb542251",
  "b0fbe152849f49034d2fa00ccc7b960fad7b30b6c4f9f2713eb01c147146ad31",
  "98508bb3590886af3be523b61c3d0ce6490bb8b27029878caec57e4c750f993d",
  "a0ca9ff75afae65598630b3b93560834c7f4dd29a557aa29c7becd49aeef3753",
  "3c5fad0516bb8ec53da1c16e910c23f792b971c7e2a0ee57d57c32e3655a646b",
};
static size_t nb_elligator_dir_vectors=28;
