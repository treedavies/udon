import json
version = "1.0"

class module:
	def __init__(self, args=None):
		self.module_args = args

	def run(self):
		if type(dict) == type(self.module_args):
			rc = "1".encode()
			data = f"null".encode()
			error = f"hello_world(): rtn() arg != dict".encode()
			return (rc, data, error)

		try:
			if "name" in self.module_args.keys():
				name = self.module_args["name"]
				data = f"Hello, {name}!"
		except Exception as e:
			rc = "1".encode()
			data = f"null".encode()
			error = f"hello_world(): rtn {e}".encode()
			return (rc, data, error)

		return ("0".encode(), data.encode(), "null".encode())

