# Guía de implementación del sistema de hooks

Este documento describe cómo implementar y utilizar el sistema de hooks para funciones tanto exportadas como internas en tu proyecto.

## Estructura del proyecto

Para implementar este sistema, deberás añadir los siguientes archivos a tu proyecto:

1. **HookManager.h/.cpp** - Clase para gestionar hooks de funciones exportadas por DLLs
2. **InternalHookManager.h/.cpp** - Clase para gestionar hooks de funciones internas
3. **pch.h** - Archivo de cabecera precompilada con las dependencias necesarias

## Dependencias necesarias

El sistema depende de la biblioteca Microsoft Detours para realizar los hooks. Asegúrate de:

1. Incluir los archivos de cabecera de Detours en tu proyecto
2. Enlazar con la biblioteca detours.lib
3. Incluir psapi.lib para acceder a GetModuleInformation

## Paso 1: Configuración del proyecto

1. **Añade la dependencia de Detours**:
   ```
   #pragma comment(lib, "detours.lib")
   #pragma comment(lib, "psapi.lib")
   ```

2. **Asegúrate de que el PCH incluya las cabeceras necesarias**:
   ```cpp
   #include <windows.h>
   #include <psapi.h>
   #include <iostream>
   #include <fstream>
   #include <string>
   #include <vector>
   #include <map>
   #include <functional>
   #include <sstream>
   #include <iomanip>
   ```

## Paso 2: Inicializar el sistema de hooks

En tu función `DllMain` o función de inicialización:

```cpp
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateConsole();  // Opcional, para debugging
        Init();  // Función donde inicializarás los hooks
        break;

    case DLL_PROCESS_DETACH:
        // Limpiar y desinstalar hooks
        if (HookManager::GetInstance()) {
            HookManager::GetInstance()->UnhookAll();
        }
        if (InternalHookManager::GetInstance()) {
            InternalHookManager::GetInstance()->UnhookAll();
        }
        break;
    }
    return TRUE;
}
```

## Paso 3: Definir las funciones hook

### Para funciones exportadas

```cpp
// Definir tipo de la función original
typedef unsigned short(__thiscall* GetProtocolID_t)(void* thisPtr);

// Implementar la función hook
unsigned short __fastcall HookedGetProtocolID(void* thisPtr, void* edx) {
    // Obtener la función original
    GetProtocolID_t original = HookManager::GetInstance()->GetOriginalFunction<GetProtocolID_t>("GetProtocolID");

    // Llamar a la función original
    unsigned short protocolID = original(thisPtr);

    // Procesar o modificar el resultado
    HookManager::GetInstance()->Log("Protocolo detectado: 0x" + std::to_string(protocolID));

    return protocolID;
}
```

### Para funciones internas

```cpp
// Definir tipo de la función interna
typedef int(__fastcall *CalculateDamage_t)(void* thisPtr, void* edx, float baseDamage, int attackType);

// Implementar la función hook
int __fastcall HookedCalculateDamage(void* thisPtr, void* edx, float baseDamage, int attackType) {
    // Obtener la función original
    CalculateDamage_t original = InternalHookManager::GetInstance()->GetOriginalFunction<CalculateDamage_t>("CalculateDamage");
    
    // Modificar parámetros si es necesario
    float modifiedDamage = baseDamage * 1.2f;
    
    // Llamar a la función original con parámetros posiblemente modificados
    int result = original(thisPtr, edx, modifiedDamage, attackType);
    
    return result;
}
```

## Paso 4: Registrar los hooks

### Hooks para funciones exportadas
```cpp
HookManager* hookManager = HookManager::GetInstance();

// Registrar un hook para una función exportada
hookManager->RegisterHook(
    "GetProtocolID",                             // ID único del hook
    "I3NETWORKDX.DLL",                           // Nombre de la DLL
    "GetProtocolID",                             // Nombre de la función
    "?GetProtocolID@i3NetworkPacket@@QAEGXZ",    // Nombre decorado (opcional)
    (void*)HookedGetProtocolID                   // Función hook
);

// Instalar todos los hooks registrados
hookManager->InstallAllHooks();
```

### Hooks para funciones internas

#### Método 1: Usando una dirección conocida
```cpp
InternalHookManager* internalHookManager = InternalHookManager::GetInstance();

// Registrar un hook usando una dirección conocida
void* functionAddress = (void*)0x12345678;  // Dirección encontrada mediante debugging
internalHookManager->RegisterHook(
    "CalculateDamage",            // ID único
    functionAddress,              // Dirección conocida
    "CalculateDamage",            // Nombre descriptivo
    (void*)HookedCalculateDamage  // Función hook
);
```

#### Método 2: Usando un patrón de bytes
```cpp
// Registrar un hook usando un patrón de bytes para encontrar la función
internalHookManager->RegisterHook(
    "RenderObject",               // ID único
    "EngineRenderer.dll",         // Módulo donde buscar (opcional)
    "RenderObject",               // Nombre descriptivo
    "pattern:55 8B EC 83 EC 14 53 56 57 8B F9 8B 5D 08", // Patrón de bytes
    (void*)HookedRenderObject     // Función hook
);
```

#### Método 3: Usando una dirección en formato hexadecimal como string
```cpp
// Registrar un hook usando una dirección en formato hexadecimal
internalHookManager->RegisterHook(
    "PhysicsCalculation",         // ID único
    "PhysicsEngine.dll",          // Módulo donde buscar (opcional)
    "PhysicsCalculation",         // Nombre descriptivo
    "0x40ABC123",                 // Dirección en formato hexadecimal
    (void*)HookedPhysicsCalculation // Función hook
);
```

## Paso 5: Conectar los sistemas de logging

Si deseas que el `InternalHookManager` utilice el mismo sistema de logging que `HookManager`:

```cpp
// Función adaptadora para la función de log de HookManager
void HookManagerLogAdapter(void* manager, const std::string& message) {
    HookManager* hookManager = static_cast<HookManager*>(manager);
    hookManager->Log(message);
}

// Conectar los sistemas de logging
internalHookManager->SetHookManager(hookManager, HookManagerLogAdapter);
```

## Paso 6: Encontrar patrones de bytes para funciones internas

Para encontrar los patrones de bytes de funciones internas, puedes usar herramientas de depuración como x64dbg, IDA Pro o Cheat Engine:

1. **Localiza la función** en el depurador
2. **Identifica el prólogo de la función** (primeros bytes)
3. **Crea un patrón** de estos bytes, usando '?' para bytes que puedan cambiar

Ejemplo de patrón:
```
"55 8B EC 83 EC 10 56 57 8B F9 8B 4D 08"
```

Los primeros bytes de una función suelen ser estables, especialmente el prólogo.

## Casos de uso comunes

### 1. Modificar parámetros de una función interna

```cpp
int __fastcall HookedCalculateDamage(void* thisPtr, void* edx, float baseDamage, int attackType) {
    CalculateDamage_t original = InternalHookManager::GetInstance()->GetOriginalFunction<CalculateDamage_t>("CalculateDamage");
    
    // Modificar el daño según condiciones
    float modifiedDamage = baseDamage;
    if (attackType == 1) { // Ataque crítico
        modifiedDamage *= 1.5f; // Aumentar daño en 50%
    }
    
    return original(thisPtr, edx, modifiedDamage, attackType);
}
```

### 2. Cambiar completamente el comportamiento

```cpp
bool __fastcall HookedIsVisibleObject(void* thisPtr, void* edx, void* object) {
    // Ignorar la función original y siempre retornar true para ver objetos ocultos
    return true;
}
```

### 3. Logging sin modificar comportamiento

```cpp
void __fastcall HookedLoadTexture(void* thisPtr, void* edx, const char* texturePath) {
    LoadTexture_t original = InternalHookManager::GetInstance()->GetOriginalFunction<LoadTexture_t>("LoadTexture");
    
    // Log para monitoreo
    InternalHookManager::GetInstance()->Log("Cargando textura: " + std::string(texturePath));
    
    // Comportamiento original sin cambios
    original(thisPtr, edx, texturePath);
}
```

## Consejos para hooks robustos

1. **Usa patrones amplios**: Incluye suficientes bytes (12-20) para que sean únicos en la memoria
2. **Evita direcciones absolutas**: Pueden cambiar entre ejecuciones
3. **Prueba en diferentes versiones**: Asegúrate de que tus patrones funcionen en todas las versiones objetivo
4. **Maneja errores adecuadamente**: Siempre verifica si el hook se instaló correctamente
5. **Libera los hooks**: Siempre desinstala los hooks antes de que tu DLL sea descargada