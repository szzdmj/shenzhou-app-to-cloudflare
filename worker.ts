{
  "name": "shenzhou-app-to-cloudflare",
  "main": "worker.ts", // 确保 worker.ts 放在项目根目录
  "compatibility_date": "2025-07-26",
  "observability": { 
         "enabled": true 
       },
  "containers": [
    {
      "max_instances": 12,
      "name": "sz-containers",
      "class_name": "SZContainer",
      "instance_type": "standard",
      "image": "./static-build-cf.Dockerfile"      
    }
  ],
  "dev": {
    "ip": "192.145.232.38",
    "port": 80,
    "local_protocol": "http"
  },
  "durable_objects": {
    "bindings": [
      {
        "name": "SZ_CONTAINER",
        "class_name": "SZContainer"
      }
    ]
  },
  "migrations": [
    {
      "tag": "v1",
      "new_sqlite_classes": [
        "SZContainer"
      ]
    }
  ]
}
