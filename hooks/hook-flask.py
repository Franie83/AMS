# hook-flask.py
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files('flask')
hiddenimports = (
    collect_submodules('flask') +
    collect_submodules('werkzeug') +
    collect_submodules('jinja2') +
    collect_submodules('markupsafe') +
    collect_submodules('click') +
    collect_submodules('itsdangerous')
)
