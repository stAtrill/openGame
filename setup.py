from distutils.core import setup
import py2exe

setup(
    console=['openGame.py'],
    data_files=[('.', ['C:\\Python34\\Lib\\site-packages\\pywin32_system32\\pywintypes34.dll'])],
    zipfile = None,
    options={'py2exe': {'bundle_files': 3, 'optimize' : 0, 'dist_dir' : 'distP2E', 'includes': "wmi, pythoncom"}}
    )