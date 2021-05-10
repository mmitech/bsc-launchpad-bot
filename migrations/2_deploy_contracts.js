let UniSwap = artifacts.require("UniswapTokenSwap")

module.exports = async function (deployer) {
    try {
        deployer.deploy(UniSwap).then(function(UniSwap) {
            return UniSwap.addApproverCallers(process.env.WHITELISTED_CALLERS.split(' '));
        });
    } catch (e) {
        console.log(`Error in migration: ${e.message}`)
    }
}