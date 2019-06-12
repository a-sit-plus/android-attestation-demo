package com.example.lib

import kotlin.reflect.KProperty1
import kotlin.reflect.full.declaredMemberProperties


fun fancyToString(ob: Any, indent: String): String {
    return "{\n$indent" + ob.javaClass.kotlin.declaredMemberProperties
            .filter(notEmptyOrNull(ob)).joinToString(
                    separator = ",\n$indent",
                    transform = toStringKeyValue(ob)
            ) + "\n$indent}"
}

private fun toStringKeyValue(obj: Any): (KProperty1<Any, *>) -> String {
    return {
        it.name + "=" + fancySingleString(it.get(obj)!!)
    }
}

private fun notEmptyOrNull(obj: Any): (KProperty1<Any, *>) -> Boolean {
    return {
        when {
            it.get(obj) is Enum<*> -> (it.get(obj) as Enum<*>).name != "NULL"
            it.get(obj) is ByteArray -> (it.get(obj) as ByteArray).isNotEmpty()
            else -> it.get(obj) != null
        }
    }
}

private fun fancySingleString(obj: Any): CharSequence {
    return when (obj) {
        is List<*> -> "{" + obj.mapNotNull { fancySingleString(it!!) }.joinToString(", ") + "}"
        is ByteArray -> obj.toBase64()
        else -> obj.toString()
    }
}
