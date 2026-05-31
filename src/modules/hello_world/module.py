version = "1.0"

class module:
	def __init__(self, args=None):
		self.module_args = args

	def run(self):
		rc = "0".encode()
		data = "null".encode()
		error = "null".encode()
		
		try:
			if self.module_args:
				name = self.module_args.decode("utf-8")
				data = f"Hello, {name}!".encode()
			else:
				data = "Hello, World!".encode()
		except Exception as e:
			rc = "1".encode()
			error = f"{e}".encode()	
			return (rc, data, error)	

		return (rc, data, error)

