from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

# Collect all data files
datas = collect_data_files('face_recognition')
datas += collect_data_files('face_recognition_models')

# Collect all submodules
hiddenimports = collect_submodules('face_recognition')
hiddenimports += collect_submodules('face_recognition_models')

# Collect dynamic libraries
binaries = collect_dynamic_libs('face_recognition')