#test_setup.py
"""
Quick setup verification script to test all components work together
"""

import os
import sys
import traceback

def test_imports():
    """Test all critical imports"""
    print("Testing imports...")
    
    try:
        import gymnasium as gym
        print("✅ gymnasium imported successfully")
    except ImportError as e:
        print(f"❌ gymnasium import failed: {e}")
        return False
    
    try:
        import stable_baselines3
        print("✅ stable_baselines3 imported successfully")
    except ImportError as e:
        print(f"❌ stable_baselines3 import failed: {e}")
        return False
    
    try:
        import numpy as np
        print("✅ numpy imported successfully")
    except ImportError as e:
        print(f"❌ numpy import failed: {e}")
        return False
    
    try:
        import torch
        print("✅ torch imported successfully")
    except ImportError as e:
        print(f"❌ torch import failed: {e}")
        return False
    
    return True

def test_environment():
    """Test environment creation and basic functionality"""
    print("\nTesting environment...")
    
    try:
        from pentest_env import PentestEnv
        print("✅ PentestEnv imported successfully")
        
        # Test environment creation
        env = PentestEnv(target="test_target", simulator_mode=True)
        print("✅ Environment created successfully")
        
        # Test reset
        obs, info = env.reset()
        print(f"✅ Reset successful: obs shape {obs.shape}, info keys: {list(info.keys())}")
        
        # Test step
        action = 0  # NMAP action
        obs, reward, terminated, truncated, info = env.step(action)
        print(f"✅ Step successful: reward={reward:.2f}, terminated={terminated}, truncated={truncated}")
        
        env.close()
        return True
        
    except Exception as e:
        print(f"❌ Environment test failed: {e}")
        traceback.print_exc()
        return False

def test_training_compatibility():
    """Test training setup without actually training"""
    print("\nTesting training compatibility...")
    
    try:
        from stable_baselines3 import PPO
        from stable_baselines3.common.vec_env import DummyVecEnv
        from stable_baselines3.common.monitor import Monitor
        from pentest_env import PentestEnv
        from train import GymnasiumCompatibilityWrapper, FixedRewardWrapper
        
        # Create wrapped environment
        def make_env():
            env = PentestEnv(target="test", simulator_mode=True)
            env = GymnasiumCompatibilityWrapper(env)
            env = FixedRewardWrapper(env)
            return Monitor(env, "./test_logs/")
        
        os.makedirs("./test_logs/", exist_ok=True)
        
        # Create vectorized environment
        env = DummyVecEnv([make_env])
        print("✅ Vectorized environment created successfully")
        
        # Test reset and step with vectorized environment
        obs = env.reset()
        print(f"✅ VecEnv reset successful: obs shape {obs.shape}")
        
        # Test step
        actions = [0]  # Single action for single environment
        obs, rewards, dones, infos = env.step(actions)
        print(f"✅ VecEnv step successful: reward={rewards[0]:.2f}, done={dones[0]}")
        
        # Create PPO model (but don't train)
        model = PPO(
            "MlpPolicy",
            env,
            verbose=0,
            learning_rate=3e-4,
            n_steps=64,  # Small for testing
            batch_size=32,
            policy_kwargs=dict(net_arch=[64, 64])
        )
        print("✅ PPO model created successfully")
        
        # Test model prediction
        action, _ = model.predict(obs)
        print(f"✅ Model prediction successful: action={action}")
        
        env.close()
        return True
        
    except Exception as e:
        print(f"❌ Training compatibility test failed: {e}")
        traceback.print_exc()
        return False

def test_tools():
    """Test individual tool functions"""
    print("\nTesting tools...")
    
    try:
        from task_nmap import execute_nmap_scan
        result = execute_nmap_scan("127.0.0.1", simulator_mode=True)
        if result and 'open_ports' in result:
            print("✅ NMAP tool working")
        else:
            print("⚠️ NMAP tool returned no results (but didn't crash)")
    except Exception as e:
        print(f"❌ NMAP tool failed: {e}")
        
    try:
        from task_gobuster import execute_gobuster_scan
        result = execute_gobuster_scan("http://127.0.0.1", simulator_mode=True)
        if result and 'found_directories' in result:
            print("✅ Gobuster tool working")
        else:
            print("⚠️ Gobuster tool returned no results (but didn't crash)")
    except Exception as e:
        print(f"❌ Gobuster tool failed: {e}")
        
    try:
        from task_crawler import crawl_site
        result = crawl_site("http://127.0.0.1", max_pages=1, delay=0.1)
        print("✅ Crawler tool working")
    except Exception as e:
        print(f"❌ Crawler tool failed: {e}")
        
    try:
        from task_xss import execute_xss_test
        import requests
        session = requests.Session()
        test_target = {"url": "http://127.0.0.1", "params": ["test"]}
        result = execute_xss_test(session, test_target, use_intelligent=False)
        print("✅ XSS tool working (may not find vulnerabilities in test)")
    except Exception as e:
        print(f"❌ XSS tool failed: {e}")

def cleanup():
    """Clean up test files"""
    import shutil
    if os.path.exists("./test_logs/"):
        shutil.rmtree("./test_logs/")
    print("✅ Test cleanup completed")

def main():
    """Run all tests"""
    print("AI Pentesting Agent - Setup Verification")
    print("=" * 50)
    
    all_passed = True
    
    # Test 1: Imports
    if not test_imports():
        all_passed = False
        print("\n❌ Import test failed. Please install missing packages:")
        print("pip install gymnasium stable-baselines3 torch numpy requests beautifulsoup4")
        return
    
    # Test 2: Environment
    if not test_environment():
        all_passed = False
        print("\n❌ Environment test failed. Check pentest_env.py")
    
    # Test 3: Training compatibility  
    if not test_training_compatibility():
        all_passed = False
        print("\n❌ Training compatibility test failed. Check train.py")
    
    # Test 4: Tools
    test_tools()
    
    # Cleanup
    cleanup()
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 ALL CRITICAL TESTS PASSED!")
        print("Your setup is ready. You can now:")
        print("  python train.py train    # Start training")
        print("  python main.py --live --target http://example.com  # Test live")
    else:
        print("❌ SOME TESTS FAILED!")
        print("Please fix the issues above before proceeding.")

if __name__ == "__main__":
    main()
