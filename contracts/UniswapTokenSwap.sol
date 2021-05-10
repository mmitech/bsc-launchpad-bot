// SPDX-License-Identifier: MIT
pragma solidity ^0.6.6;

import "./SafeMath.sol";
import "./IERC20.sol";
import "./IUniswapV2Router02.sol";
import "./Ownable.sol";

contract UniswapTokenSwap is Ownable {
    using SafeMath for uint256;
    address public UNISWAP_ROUTER_ADDRESS;
    IUniswapV2Router02 public uniswapRouter;
    Projects[] public projects;
    
    constructor() public {
        UNISWAP_ROUTER_ADDRESS = 0x10ED43C718714eb63d5aA57B78B54704E256024E;
        uniswapRouter = IUniswapV2Router02(UNISWAP_ROUTER_ADDRESS);
    }

    struct Projects {
        address token; 
        uint256 amountSpent;
        uint256 amountBought;
    }

    function SwapETHtoToken(address _token, uint256 _amountToSpend, uint256 _maxTokenPrice) public payable onlyApproverCallers {
        require(!isBought(_token), "token already bought");
        uint256 estimate = getEstimatedERC20forETH(_token, 1e18);
        require(_maxTokenPrice >= estimate, "Price is too high");
        uint256 deadline = block.timestamp + 6;
        uint256 amountOut = getEstimatedETHforERC20(_token, _amountToSpend);
        address[] memory path = getPathFromETHtoERC20(_token);
        uint[] memory amounts = uniswapRouter.swapETHForExactTokens{value: _amountToSpend}(amountOut, path, address(this), deadline);
        uint256 amountSpent = amounts[0];
        uint256 amountBought = amounts[amounts.length - 1];
        setProjectBought(_token, amountSpent, amountBought);
    }

    function swapExactERC20toETH(address _token, uint256 _amountIn) public payable onlyApproverCallers {
        uint256 deadline = block.timestamp + 6;
        IERC20 token = IERC20(_token);
        token.approve(UNISWAP_ROUTER_ADDRESS, _amountIn);
        address[] memory path = getPathFromERC20toETH(_token);
        uint256 amountOutMin = getEstimatedERC20forETH(_token, _amountIn);
        uniswapRouter.swapExactTokensForETH(_amountIn, amountOutMin, path, address(this), deadline);
    }

    function swapExactERC20toERC20(address _tokenIn, address _tokenOut, uint256 _amountIn) public payable onlyApproverCallers {
        uint256 deadline = block.timestamp + 6;
        IERC20 tokenIn = IERC20(_tokenIn);
        tokenIn.approve(UNISWAP_ROUTER_ADDRESS, _amountIn);
        address[] memory path = getPathFromERC20toERC20(_tokenIn, _tokenOut);
        uint256 amountOutMin = getEstimatedERC20forERC20(_tokenIn, _tokenOut, _amountIn);
        uniswapRouter.swapExactTokensForTokens(_amountIn, amountOutMin, path, address(this), deadline);
    }

    function getEstimatedETHforERC20(address _token, uint256 _amount) public view returns (uint) {
        uint[] memory estimated = uniswapRouter.getAmountsOut(_amount, getPathFromETHtoERC20(_token));
        return estimated[1];
    }

    function getEstimatedERC20forETH(address _token, uint256 _amount) public view returns (uint) {
        uint[] memory estimated = uniswapRouter.getAmountsOut(_amount, getPathFromERC20toETH(_token));
        return estimated[1];
    }

    function getEstimatedERC20forERC20(address _tokenIn, address _tokenOut, uint256 _amount) public view returns (uint) {
        uint[] memory estimated = uniswapRouter.getAmountsOut(_amount, getPathFromERC20toERC20(_tokenIn, _tokenOut));
        return estimated[1];
    }

    function getPathFromETHtoERC20(address _token) private view returns (address[] memory) {
        address[] memory path = new address[](2);
        path[0] = uniswapRouter.WETH();
        path[1] = _token;
        return path;
    }

    function getPathFromERC20toETH(address _token) private view returns (address[] memory) {
        address[] memory path = new address[](2);
        path[0] = _token;
        path[1] = uniswapRouter.WETH();
        return path;
    }

    function getPathFromERC20toERC20(address _tokenIn, address _tokenOut) private pure returns (address[] memory) {
        address[] memory path = new address[](2);
        path[0] = _tokenIn;
        path[1] = _tokenOut;
        return path;
    }

    function setProjectBought(address _token, uint256 _amountSpent, uint256 _amountBought) private {
        require(!isBought(_token), "token already bought");
        projects.push(
            Projects({
                token: _token,
                amountSpent: _amountSpent,
                amountBought: _amountBought
            })
        );
    }

    function removeProjectBought(address _token) external onlyOwner {
        require(isBought(_token), "token doesn't exist");
        for (uint256 _pid = 0; _pid < projects.length; _pid++) {
            if (projects[_pid].token == _token) {
                projects[_pid] = projects[projects.length-1];
                projects.pop();
            }
        }
    }

    function isBought(address _token) public view returns (bool) {
        for (uint256 _pid = 0; _pid < projects.length; _pid++) {
            if (projects[_pid].token == _token) return true;
        }
        return false;
    }

    function projectsLength() external view returns (uint256) {
        return projects.length;
    }

    function changeRouter(address _UNISWAP_ROUTER_ADDRESS) public onlyOwner {
        UNISWAP_ROUTER_ADDRESS = _UNISWAP_ROUTER_ADDRESS;
        uniswapRouter = IUniswapV2Router02(UNISWAP_ROUTER_ADDRESS);
    }

    // fallback function
    receive() payable external {}

    function withdrawETH() external payable onlyOwner {
        require(address(this).balance > 0, "balance is 0");
        msg.sender.transfer(address(this).balance);
    }

    function withdrawERC20(IERC20 token) external payable onlyOwner {
        require(token.balanceOf(address(this)) > 0, "token balance is 0");
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}