from PyInstaller.utils.hooks import collect_data_files

# This tells PyInstaller to include all data files from the face_recognition_models package
datas = collect_data_files('face_recognition_models')