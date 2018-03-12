import setuptools



setuptools.setup(
    package_dir={'': 'src'},
    packages=setuptools.find_packages('src'),
    include_package_data=True,
    namespace_packages=[],
    scripts=['src/apk_bitminer/pydexdump',
             'src/apk_bitminer/pyaxmldump']
)
