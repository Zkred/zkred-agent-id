export const config = {
  chains: [
    {
      name: "polygon-amoy",
      rpcUrl: "https://rpc-amoy.polygon.technology",
      chainId: 80002,
      identityRegistryV1: "0x304eEa4f6f32e3a7B270DBf292D5f4eeeFe55873",
      identityRegistryProxy: "0xb75eB3D776711E87240E5ff6DA7B81e12fd37f83",
    },
    {
      name: "sepolia",
      chainId: 11155111,
      rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
      identityRegistryV1: "0x5fcDB5665F62fAf9DD3121BBd21ddAD17694ED2E",
      identityRegistryProxy: "0x1CceBD36C61ee36629073f297682AE63E7eAEC84",
    },
    {
      name: "hedera",
      chainId: 296,
      rpcUrl: "https://testnet.hashio.io/api",
      identityRegistryV1: "0x266cd7890184A012692803422532370a867739EA",
      identityRegistryProxy: "0x5c282DA873A9f87C702d39CfdF12cAe2deC9eFD2",
    },
    {
      //todo: deployment pending
      name: "skaleBaseSepolia",
      chainId: 324705682,
      rpcUrl:
        "https://base-sepolia-testnet.skalenodes.com/v1/jubilant-horrible-ancha",
      identityRegistryV1: "0x4FF67C5E06298Ff56A3a000AB40113D2C8380951",
      identityRegistryProxy: "",
    },
    {
      name: "arbitrumSepolia",
      chainId: 421614,
      rpcUrl: "https://endpoints.omniatech.io/v1/arbitrum/sepolia/public",
      identityRegistryV1: "0xFbFe1BDFe13624B153B9590d7a19c4E4A53B1D04",
      identityRegistryProxy: "0x9CBa4f02F33A9e79052d422B3C9526B407d96A93",
    },
    {
      name: "baseSepolia",
      chainId: 84532,
      rpcUrl: "https://base-sepolia-public.nodies.app",
      identityRegistryV1: "0x1355A5EB488769448fAEF3652E8F77Ec58Eb8C44",
      identityRegistryProxy: "0xFbFe1BDFe13624B153B9590d7a19c4E4A53B1D04",
    },
  ],
};
